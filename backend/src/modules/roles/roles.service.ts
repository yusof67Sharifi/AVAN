import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { AuditService } from '../../common/services/audit.service';
import { AppException } from '../../common/exceptions/app.exception';
import { PermissionsService } from '../permissions/permissions.service';
import { CreateRoleDto, UpdateRoleDto } from './dto/roles.dto';
import { UserRole, RoleScope, Prisma } from '@prisma/client';

export interface RoleActor {
  userId: string;
  role: UserRole;
  zoneId?: string;
  companyId?: string;
}

@Injectable()
export class RolesService {
  private readonly logger = new Logger(RolesService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly permissionsService: PermissionsService,
  ) {}

  private buildScopeWhere(actor: RoleActor): Prisma.RoleWhereInput {
    if (actor.role === UserRole.SUPER_ADMIN) return {};
    if (actor.role === UserRole.ZONE_MANAGER) {
      return { OR: [{ scopeType: RoleScope.GLOBAL }, { scopeType: RoleScope.ZONE, zoneId: actor.zoneId }] };
    }
    if (actor.role === UserRole.COMPANY_ADMIN) {
      return {
        OR: [
          { scopeType: RoleScope.GLOBAL },
          { scopeType: RoleScope.COMPANY, companyId: actor.companyId },
        ],
      };
    }
    return { scopeType: RoleScope.GLOBAL };
  }

  async listRoles(actor: RoleActor) {
    const where = this.buildScopeWhere(actor);
    return this.prisma.role.findMany({
      where,
      include: { _count: { select: { assignments: true, permissions: true } } },
      orderBy: { createdAt: 'asc' },
    });
  }

  /**
   * Central tenant-isolation check. Out-of-scope access is reported as
   * ROLE_NOT_FOUND so the existence of other tenants' roles is never revealed.
   * GLOBAL roles are read-only for tenant admins (write attempts →
   * ROLE_SCOPE_VIOLATION). SUPER_ADMIN is exempt from every restriction.
   */
  private assertRoleAccessible(
    role: { scopeType?: RoleScope; zoneId?: string | null; companyId?: string | null },
    actor: RoleActor,
    { write }: { write?: boolean } = {},
  ): void {
    if (actor.role === UserRole.SUPER_ADMIN) return;

    if (actor.role !== UserRole.ZONE_MANAGER && actor.role !== UserRole.COMPANY_ADMIN) {
      // No other roles may use this service.
      throw new AppException('ROLE_NOT_FOUND');
    }

    const readable =
      (actor.role === UserRole.ZONE_MANAGER &&
        (role.scopeType === RoleScope.GLOBAL ||
          (role.scopeType === RoleScope.ZONE && role.zoneId === actor.zoneId))) ||
      (actor.role === UserRole.COMPANY_ADMIN &&
        (role.scopeType === RoleScope.GLOBAL ||
          (role.scopeType === RoleScope.COMPANY && role.companyId === actor.companyId)));

    if (!readable) throw new AppException('ROLE_NOT_FOUND');

    if (write && role.scopeType === RoleScope.GLOBAL) {
      throw new AppException('ROLE_SCOPE_VIOLATION');
    }
  }

  async getRoleById(id: string, actor: RoleActor, { write }: { write?: boolean } = {}) {
    const role = await this.prisma.role.findUnique({
      where: { id },
      include: { permissions: { select: { permission: true } } },
    });
    if (!role) throw new AppException('ROLE_NOT_FOUND');
    this.assertRoleAccessible(role, actor, { write });
    return role;
  }

  async createRole(dto: CreateRoleDto, actor: RoleActor) {
    let scopeType = dto.scopeType || RoleScope.GLOBAL;
    let zoneId = dto.zoneId || null;
    let companyId = dto.companyId || null;

    if (actor.role === UserRole.ZONE_MANAGER) {
      if (dto.scopeType === RoleScope.COMPANY) throw new AppException('ROLE_SCOPE_VIOLATION');
      scopeType = RoleScope.ZONE;
      zoneId = actor.zoneId || null;
      companyId = null;
    } else if (actor.role === UserRole.COMPANY_ADMIN) {
      scopeType = RoleScope.COMPANY;
      zoneId = null;
      companyId = actor.companyId || null;
    }

    const existing = await this.prisma.role.findFirst({
      where: { name: dto.name, zoneId, companyId },
    });
    if (existing) throw new AppException('ROLE_NAME_TAKEN');

    const role = await this.prisma.role.create({
      data: {
        name: dto.name,
        nameFa: dto.nameFa,
        description: dto.description || null,
        scopeType,
        zoneId,
        companyId,
      },
    });

    await this.audit.log({
      userId: actor.userId,
      targetId: role.id,
      targetType: 'Role',
      action: 'ROLE_CREATED',
      metadata: { name: dto.name, scopeType },
    });

    return role;
  }

  async updateRole(id: string, dto: UpdateRoleDto, actor: RoleActor) {
    const role = await this.getRoleById(id, actor, { write: true });
    if (role.isSystem && dto.name && dto.name !== role.name) {
      throw new AppException('ROLE_IS_SYSTEM');
    }

    const updated = await this.prisma.role.update({
      where: { id },
      data: {
        ...(dto.name !== undefined && { name: dto.name }),
        ...(dto.nameFa !== undefined && { nameFa: dto.nameFa }),
        ...(dto.description !== undefined && { description: dto.description }),
      },
    });

    await this.audit.log({
      userId: actor.userId,
      targetId: id,
      targetType: 'Role',
      action: 'ROLE_UPDATED',
      metadata: dto as any,
    });

    return updated;
  }

  async deleteRole(id: string, actor: RoleActor) {
    const role = await this.getRoleById(id, actor, { write: true });
    if (role.isSystem) throw new AppException('ROLE_IS_SYSTEM');

    await this.prisma.$transaction([
      this.prisma.roleAssignment.deleteMany({ where: { roleId: id } }),
      this.prisma.rolePermission.deleteMany({ where: { roleId: id } }),
      this.prisma.role.delete({ where: { id } }),
    ]);

    await this.audit.log({
      userId: actor.userId,
      targetId: id,
      targetType: 'Role',
      action: 'ROLE_DELETED',
      metadata: { name: role.name },
    });
  }

  async getRolePermissions(id: string, actor: RoleActor): Promise<string[]> {
    const role = await this.getRoleById(id, actor);
    return role.permissions.map((p) => p.permission);
  }

  async setRolePermissions(id: string, permissions: string[], actor: RoleActor) {
    const role = await this.getRoleById(id, actor, { write: true });

    // Tenant admins may never attach permissions beyond their own authority;
    // the submitted list must be a subset of the actor's effective set.
    if (actor.role !== UserRole.SUPER_ADMIN) {
      const ownPermissions = new Set(await this.permissionsService.getUserPermissions(actor.userId));
      const beyondAuthority = permissions.filter((p) => !ownPermissions.has(p));
      if (beyondAuthority.length > 0) throw new AppException('ROLE_SCOPE_VIOLATION');
    }

    const assigned = await this.prisma.roleAssignment.findMany({
      where: { roleId: id },
      select: { userId: true },
    });

    await this.prisma.$transaction(async (tx) => {
      await tx.rolePermission.deleteMany({ where: { roleId: id } });
      if (permissions.length > 0) {
        await tx.rolePermission.createMany({
          data: permissions.map((perm) => ({ roleId: id, permission: perm })),
        });
      }
    });

    for (const a of assigned) {
      await this.permissionsService.invalidateUserPermissions(a.userId);
    }

    await this.audit.log({
      userId: actor.userId,
      targetId: id,
      targetType: 'Role',
      action: 'ROLE_PERMISSIONS_SET',
      metadata: { permissions },
    });

    return { roleId: id, permissions };
  }

  async assignRole(roleId: string, userId: string, actor: RoleActor) {
    const role = await this.getRoleById(roleId, actor, { write: true });

    const targetUser = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!targetUser || targetUser.deletedAt) throw new AppException('USER_NOT_FOUND');

    if (actor.role !== UserRole.SUPER_ADMIN) {
      if (actor.role === UserRole.ZONE_MANAGER && targetUser.zoneId !== actor.zoneId) {
        throw new AppException('USER_TARGET_OUT_OF_SCOPE');
      }
      if (actor.role === UserRole.COMPANY_ADMIN && targetUser.companyId !== actor.companyId) {
        throw new AppException('USER_TARGET_OUT_OF_SCOPE');
      }
      if (targetUser.role === UserRole.SUPER_ADMIN) {
        throw new AppException('USER_PERMISSION_DENIED');
      }
      // Cross-tenant assignment guard: the target user must belong to the
      // administrative scope of the role being assigned (defense-in-depth —
      // roles of other tenants can no longer be resolved, so this matches
      // reachability of the current actor's tenants only).
      if (
        (role.scopeType === RoleScope.ZONE && role.zoneId !== targetUser.zoneId) ||
        (role.scopeType === RoleScope.COMPANY && role.companyId !== targetUser.companyId)
      ) {
        throw new AppException('USER_TARGET_OUT_OF_SCOPE');
      }
    }

    const existing = await this.prisma.roleAssignment.findUnique({
      where: { userId_roleId: { userId, roleId } },
    });
    if (existing) return existing;

    const assignment = await this.prisma.roleAssignment.create({
      data: { userId, roleId, assignedBy: actor.userId },
    });

    await this.permissionsService.invalidateUserPermissions(userId);

    await this.audit.log({
      userId: actor.userId,
      targetId: userId,
      targetType: 'User',
      action: 'ROLE_ASSIGNED',
      metadata: { roleId, roleName: role.nameFa },
    });

    return assignment;
  }

  async unassignRole(roleId: string, userId: string, actor: RoleActor) {
    const role = await this.getRoleById(roleId, actor, { write: true });

    await this.prisma.roleAssignment.deleteMany({ where: { userId, roleId } });

    await this.permissionsService.invalidateUserPermissions(userId);

    await this.audit.log({
      userId: actor.userId,
      targetId: userId,
      targetType: 'User',
      action: 'ROLE_UNASSIGNED',
      metadata: { roleId, roleName: role.nameFa },
    });
  }

  async getRoleUsers(id: string, actor: RoleActor) {
    await this.getRoleById(id, actor);
    return this.prisma.user.findMany({
      where: {
        roleAssignments: { some: { roleId: id } },
      },
      select: {
        id: true,
        email: true,
        phone: true,
        firstName: true,
        lastName: true,
        role: true,
        zoneId: true,
        companyId: true,
        status: true,
        avatarKey: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }
}
