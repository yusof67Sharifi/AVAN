import { Test, TestingModule } from '@nestjs/testing';
import { RolesService, RoleActor } from './roles.service';
import { PrismaService } from '../../prisma/prisma.service';
import { AuditService } from '../../common/services/audit.service';
import { PermissionsService } from '../permissions/permissions.service';
import { UserRole, RoleScope } from '@prisma/client';
import { AppException } from '../../common/exceptions/app.exception';

describe('RolesService', () => {
  let service: RolesService;
  let prisma: any;
  let audit: any;
  let permissionsService: any;

  beforeEach(async () => {
    prisma = {
      role: {
        findMany: jest.fn(),
        findUnique: jest.fn(),
        findFirst: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
      roleAssignment: {
        findMany: jest.fn(),
        findUnique: jest.fn(),
        create: jest.fn(),
        deleteMany: jest.fn(),
      },
      rolePermission: {
        findMany: jest.fn(),
        deleteMany: jest.fn(),
        createMany: jest.fn(),
      },
      user: {
        findUnique: jest.fn(),
      },
      $transaction: jest.fn().mockImplementation((fnOrArray) => {
        if (typeof fnOrArray === 'function') {
          return fnOrArray(prisma);
        }
        return Promise.all(fnOrArray);
      }),
    };

    audit = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    permissionsService = {
      getUserPermissions: jest.fn().mockResolvedValue([]),
      invalidateUserPermissions: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RolesService,
        { provide: PrismaService, useValue: prisma },
        { provide: AuditService, useValue: audit },
        { provide: PermissionsService, useValue: permissionsService },
      ],
    }).compile();

    service = module.get<RolesService>(RolesService);
  });

  describe('listRoles (scoping)', () => {
    it('SUPER_ADMIN should see all roles with empty where clause', async () => {
      prisma.role.findMany.mockResolvedValue([]);
      const actor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };

      await service.listRoles(actor);

      expect(prisma.role.findMany).toHaveBeenCalledWith({
        where: {},
        include: { _count: { select: { assignments: true, permissions: true } } },
        orderBy: { createdAt: 'asc' },
      });
    });

    it('ZONE_MANAGER should see GLOBAL roles and their zone roles', async () => {
      prisma.role.findMany.mockResolvedValue([]);
      const actor: RoleActor = {
        userId: 'zm-1',
        role: UserRole.ZONE_MANAGER,
        zoneId: 'zone-123',
      };

      await service.listRoles(actor);

      expect(prisma.role.findMany).toHaveBeenCalledWith({
        where: {
          OR: [
            { scopeType: RoleScope.GLOBAL },
            { scopeType: RoleScope.ZONE, zoneId: 'zone-123' },
          ],
        },
        include: { _count: { select: { assignments: true, permissions: true } } },
        orderBy: { createdAt: 'asc' },
      });
    });

    it('COMPANY_ADMIN should see GLOBAL roles and their company roles', async () => {
      prisma.role.findMany.mockResolvedValue([]);
      const actor: RoleActor = {
        userId: 'ca-1',
        role: UserRole.COMPANY_ADMIN,
        companyId: 'company-456',
      };

      await service.listRoles(actor);

      expect(prisma.role.findMany).toHaveBeenCalledWith({
        where: {
          OR: [
            { scopeType: RoleScope.GLOBAL },
            { scopeType: RoleScope.COMPANY, companyId: 'company-456' },
          ],
        },
        include: { _count: { select: { assignments: true, permissions: true } } },
        orderBy: { createdAt: 'asc' },
      });
    });
  });

  describe('createRole', () => {
    it('should disallow ZONE_MANAGER from creating COMPANY scoped role', async () => {
      const actor: RoleActor = {
        userId: 'zm-1',
        role: UserRole.ZONE_MANAGER,
        zoneId: 'zone-123',
      };

      await expect(
        service.createRole(
          { name: 'accountant', nameFa: 'حسابدار', scopeType: RoleScope.COMPANY },
          actor,
        ),
      ).rejects.toThrow(AppException);
    });

    it('should throw ROLE_NAME_TAKEN if role name already exists in same scope', async () => {
      const actor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };
      prisma.role.findFirst.mockResolvedValue({ id: 'existing-id' });

      await expect(
        service.createRole({ name: 'finance_viewer', nameFa: 'مشاهده‌گر مالی' }, actor),
      ).rejects.toThrow(AppException);
    });

    it('should create role successfully and log audit', async () => {
      const actor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };
      prisma.role.findFirst.mockResolvedValue(null);
      const createdRole = {
        id: 'new-role-id',
        name: 'custom_role',
        nameFa: 'نقش سفارشی',
        scopeType: RoleScope.GLOBAL,
      };
      prisma.role.create.mockResolvedValue(createdRole);

      const result = await service.createRole(
        { name: 'custom_role', nameFa: 'نقش سفارشی' },
        actor,
      );

      expect(result).toEqual(createdRole);
      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'admin-1',
          targetId: 'new-role-id',
          action: 'ROLE_CREATED',
        }),
      );
    });
  });

  describe('updateRole & deleteRole (isSystem protection)', () => {
    it('should reject renaming a system role', async () => {
      const actor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };
      prisma.role.findUnique.mockResolvedValue({
        id: 'sys-role-1',
        name: 'super_admin',
        isSystem: true,
        permissions: [],
      });

      await expect(
        service.updateRole('sys-role-1', { name: 'renamed_admin' }, actor),
      ).rejects.toThrow(AppException);
    });

    it('should reject deleting a system role', async () => {
      const actor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };
      prisma.role.findUnique.mockResolvedValue({
        id: 'sys-role-1',
        name: 'super_admin',
        isSystem: true,
        permissions: [],
      });

      await expect(service.deleteRole('sys-role-1', actor)).rejects.toThrow(AppException);
    });

    it('should delete non-system role and cascade relations in transaction', async () => {
      const actor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };
      prisma.role.findUnique.mockResolvedValue({
        id: 'custom-role-1',
        name: 'custom_role',
        isSystem: false,
        permissions: [],
      });

      await service.deleteRole('custom-role-1', actor);

      expect(prisma.$transaction).toHaveBeenCalled();
      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'admin-1',
          targetId: 'custom-role-1',
          action: 'ROLE_DELETED',
        }),
      );
    });
  });

  describe('setRolePermissions & cache invalidation', () => {
    it('should replace permissions and invalidate cache for all assigned users', async () => {
      const actor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-1',
        name: 'finance_operator',
        isSystem: false,
        permissions: [],
      });
      prisma.roleAssignment.findMany.mockResolvedValue([
        { userId: 'user-a' },
        { userId: 'user-b' },
      ]);

      const newPerms = ['finance.invoices.view', 'finance.invoices.create'];
      await service.setRolePermissions('role-1', newPerms, actor);

      expect(permissionsService.invalidateUserPermissions).toHaveBeenCalledWith('user-a');
      expect(permissionsService.invalidateUserPermissions).toHaveBeenCalledWith('user-b');
      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'ROLE_PERMISSIONS_SET',
        }),
      );
    });
  });

  describe('assignRole (scoping checks)', () => {
    it('should throw USER_TARGET_OUT_OF_SCOPE when ZONE_MANAGER assigns to user outside their zone', async () => {
      const actor: RoleActor = {
        userId: 'zm-1',
        role: UserRole.ZONE_MANAGER,
        zoneId: 'zone-A',
      };
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-1',
        name: 'guard',
        nameFa: 'نگهبان',
        scopeType: RoleScope.ZONE,
        zoneId: 'zone-A',
        companyId: null,
        permissions: [],
      });
      prisma.user.findUnique.mockResolvedValue({
        id: 'user-diff-zone',
        zoneId: 'zone-B',
        companyId: null,
        role: UserRole.ZONE_OPERATOR,
        deletedAt: null,
      });

      await expect(service.assignRole('role-1', 'user-diff-zone', actor)).rejects.toThrow(
        AppException,
      );
    });

    it('should throw USER_TARGET_OUT_OF_SCOPE when COMPANY_ADMIN assigns to user outside their company', async () => {
      const actor: RoleActor = {
        userId: 'ca-1',
        role: UserRole.COMPANY_ADMIN,
        companyId: 'company-A',
      };
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-1',
        name: 'clerk',
        nameFa: 'کارمند',
        scopeType: RoleScope.COMPANY,
        zoneId: null,
        companyId: 'company-A',
        permissions: [],
      });
      prisma.user.findUnique.mockResolvedValue({
        id: 'user-diff-company',
        zoneId: null,
        companyId: 'company-B',
        role: UserRole.COMPANY_STAFF,
        deletedAt: null,
      });

      await expect(service.assignRole('role-1', 'user-diff-company', actor)).rejects.toThrow(
        AppException,
      );
    });

    it('should throw USER_PERMISSION_DENIED when non-super-admin attempts to assign role to a SUPER_ADMIN user', async () => {
      const actor: RoleActor = {
        userId: 'zm-1',
        role: UserRole.ZONE_MANAGER,
        zoneId: 'zone-A',
      };
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-1',
        name: 'manager',
        nameFa: 'مدیر',
        permissions: [],
      });
      prisma.user.findUnique.mockResolvedValue({
        id: 'super-admin-user',
        zoneId: 'zone-A',
        role: UserRole.SUPER_ADMIN,
        deletedAt: null,
      });

      await expect(service.assignRole('role-1', 'super-admin-user', actor)).rejects.toThrow(
        AppException,
      );
    });

    it('should successfully assign role, invalidate cache, and log audit', async () => {
      const actor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-1',
        name: 'finance_clerk',
        nameFa: 'کارشناس مالی',
        permissions: [],
      });
      prisma.user.findUnique.mockResolvedValue({
        id: 'target-user-1',
        role: UserRole.COMPANY_STAFF,
        deletedAt: null,
      });
      prisma.roleAssignment.findUnique.mockResolvedValue(null);
      prisma.roleAssignment.create.mockResolvedValue({
        userId: 'target-user-1',
        roleId: 'role-1',
        assignedBy: 'admin-1',
      });

      const res = await service.assignRole('role-1', 'target-user-1', actor);

      expect(res).toBeDefined();
      expect(permissionsService.invalidateUserPermissions).toHaveBeenCalledWith('target-user-1');
      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'admin-1',
          targetId: 'target-user-1',
          action: 'ROLE_ASSIGNED',
        }),
      );
    });
  });

  describe('RBAC tenant isolation (SEC fix)', () => {
    const zoneActor: RoleActor = {
      userId: 'zm-1',
      role: UserRole.ZONE_MANAGER,
      zoneId: 'zone-123',
    };
    const companyActor: RoleActor = {
      userId: 'ca-1',
      role: UserRole.COMPANY_ADMIN,
      companyId: 'company-456',
    };

    it('(a) ZONE_MANAGER can read a role in their own zone', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-z',
        name: 'zone_clerk',
        nameFa: 'کارمند زون',
        scopeType: RoleScope.ZONE,
        zoneId: 'zone-123',
        companyId: null,
        isSystem: false,
        permissions: [],
      });

      const role = await service.getRoleById('role-z', zoneActor);

      expect(role.id).toBe('role-z');
    });

    it('(b) ZONE_MANAGER cannot read a ZONE role of another zone (ROLE_NOT_FOUND)', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-other-zone',
        name: 'other_zone_role',
        nameFa: 'نقش زون دیگر',
        scopeType: RoleScope.ZONE,
        zoneId: 'zone-B',
        companyId: null,
        isSystem: false,
        permissions: [],
      });

      await expect(service.getRoleById('role-other-zone', zoneActor)).rejects.toMatchObject({
        code: 'ROLE_NOT_FOUND',
      });
    });

    it('(b) ZONE_MANAGER cannot delete another zone’s role (ROLE_NOT_FOUND)', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-other-zone',
        name: 'other_zone_role',
        nameFa: 'نقش زون دیگر',
        scopeType: RoleScope.ZONE,
        zoneId: 'zone-B',
        companyId: null,
        isSystem: false,
        permissions: [],
      });

      await expect(service.deleteRole('role-other-zone', zoneActor)).rejects.toMatchObject({
        code: 'ROLE_NOT_FOUND',
      });
    });

    it('(c) COMPANY_ADMIN cannot read or update a COMPANY role of another company (ROLE_NOT_FOUND)', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-other-company',
        name: 'other_company_role',
        nameFa: 'نقش شرکت دیگر',
        scopeType: RoleScope.COMPANY,
        zoneId: null,
        companyId: 'company-B',
        isSystem: false,
        permissions: [],
      });

      await expect(service.getRoleById('role-other-company', companyActor)).rejects.toMatchObject({
        code: 'ROLE_NOT_FOUND',
      });
      await expect(
        service.updateRole('role-other-company', { name: 'hijack' }, companyActor),
      ).rejects.toMatchObject({ code: 'ROLE_NOT_FOUND' });
    });

    it('(d) ZONE_MANAGER can read a GLOBAL role but not update or set its permissions', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-global',
        name: 'global_role',
        nameFa: 'نقش سراسری',
        scopeType: RoleScope.GLOBAL,
        zoneId: null,
        companyId: null,
        isSystem: false,
        permissions: [],
      });

      await expect(service.getRoleById('role-global', zoneActor)).resolves.toMatchObject({
        id: 'role-global',
      });
      await expect(
        service.updateRole('role-global', { name: 'renamed' }, zoneActor),
      ).rejects.toMatchObject({ code: 'ROLE_SCOPE_VIOLATION' });
      await expect(
        service.setRolePermissions('role-global', ['zone.visitors.view'], zoneActor),
      ).rejects.toMatchObject({ code: 'ROLE_SCOPE_VIOLATION' });
    });

    it('(e) tenant admin cannot attach permissions beyond own authority (ROLE_SCOPE_VIOLATION)', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-z',
        name: 'zone_clerk',
        nameFa: 'کارمند زون',
        scopeType: RoleScope.ZONE,
        zoneId: 'zone-123',
        companyId: null,
        isSystem: false,
        permissions: [],
      });
      permissionsService.getUserPermissions.mockResolvedValue(['zone.visitors.view']);

      await expect(
        service.setRolePermissions(
          'role-z',
          ['zone.visitors.view', 'finance.invoices.create'],
          zoneActor,
        ),
      ).rejects.toMatchObject({ code: 'ROLE_SCOPE_VIOLATION' });
      expect(prisma.rolePermission.deleteMany).not.toHaveBeenCalled();
    });

    it('(e) tenant admin can set permissions that are a subset of own authority', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-z',
        name: 'zone_clerk',
        nameFa: 'کارمند زون',
        scopeType: RoleScope.ZONE,
        zoneId: 'zone-123',
        companyId: null,
        isSystem: false,
        permissions: [],
      });
      permissionsService.getUserPermissions.mockResolvedValue(['zone.visitors.view']);
      prisma.roleAssignment.findMany.mockResolvedValue([]);

      const result = await service.setRolePermissions('role-z', ['zone.visitors.view'], zoneActor);

      expect(result).toEqual({ roleId: 'role-z', permissions: ['zone.visitors.view'] });
      expect(prisma.rolePermission.createMany).toHaveBeenCalledWith({
        data: [{ roleId: 'role-z', permission: 'zone.visitors.view' }],
      });
      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'ROLE_PERMISSIONS_SET' }),
      );
    });

    it('(f) assignRole rejects cross-tenant assignment (ZONE role zone-A → user in zone-B)', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-zone-a',
        name: 'zone_a_role',
        nameFa: 'نقش زون A',
        scopeType: RoleScope.ZONE,
        zoneId: 'zone-A',
        companyId: null,
        permissions: [],
      });
      prisma.user.findUnique.mockResolvedValue({
        id: 'user-zone-b',
        zoneId: 'zone-B',
        companyId: null,
        role: UserRole.ZONE_OPERATOR,
        deletedAt: null,
      });

      await expect(
        service.assignRole('role-zone-a', 'user-zone-b', {
          userId: 'zm-1',
          role: UserRole.ZONE_MANAGER,
          zoneId: 'zone-A',
        }),
      ).rejects.toMatchObject({ code: 'USER_TARGET_OUT_OF_SCOPE' });
      expect(prisma.roleAssignment.create).not.toHaveBeenCalled();
    });

    it('(f) assignRole rejects company role assigned to user of another scope', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-company-a',
        name: 'company_a_role',
        nameFa: 'نقش شرکت A',
        scopeType: RoleScope.COMPANY,
        zoneId: null,
        companyId: 'company-A',
        permissions: [],
      });
      // ZONE_MANAGER cannot even access a COMPANY role → ROLE_NOT_FOUND
      prisma.user.findUnique.mockResolvedValue({
        id: 'user-zone-b',
        zoneId: 'zone-123',
        companyId: null,
        role: UserRole.ZONE_OPERATOR,
        deletedAt: null,
      });
      const zmActor: RoleActor = {
        userId: 'zm-1',
        role: UserRole.ZONE_MANAGER,
        zoneId: 'zone-123',
      };

      await expect(service.assignRole('role-company-a', 'user-zone-b', zmActor)).rejects.toMatchObject(
        { code: 'ROLE_NOT_FOUND' },
      );

      // COMPANY_ADMIN's own company role must not be attachable to another company's user
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-company-own',
        name: 'own_company_role',
        nameFa: 'نقش شرکت خود',
        scopeType: RoleScope.COMPANY,
        zoneId: null,
        companyId: 'company-456',
        permissions: [],
      });
      prisma.user.findUnique.mockResolvedValue({
        id: 'user-other-company',
        zoneId: null,
        companyId: 'company-B',
        role: UserRole.COMPANY_STAFF,
        deletedAt: null,
      });
      await expect(
        service.assignRole('role-company-own', 'user-other-company', companyActor),
      ).rejects.toMatchObject({ code: 'USER_TARGET_OUT_OF_SCOPE' });
      expect(prisma.roleAssignment.create).not.toHaveBeenCalled();
    });

    it('(g) createRole: DTO-supplied scopeType/zoneId/companyId never override actor scope', async () => {
      prisma.role.findFirst.mockResolvedValue(null);
      prisma.role.create.mockResolvedValue({ id: 'new-role' });

      await service.createRole(
        {
          name: 'custom_clerk',
          nameFa: 'کارمند سفارشی',
          scopeType: RoleScope.GLOBAL,
          zoneId: 'zone-B',
          companyId: 'company-B',
        },
        zoneActor,
      );

      expect(prisma.role.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          scopeType: RoleScope.ZONE,
          zoneId: 'zone-123',
          companyId: null,
        }),
      });
      expect(prisma.role.findFirst).toHaveBeenCalledWith({
        where: { name: 'custom_clerk', zoneId: 'zone-123', companyId: null },
      });
    });

    it('(g) createRole: COMPANY_ADMIN scope comes from actor, not DTO', async () => {
      prisma.role.findFirst.mockResolvedValue(null);
      prisma.role.create.mockResolvedValue({ id: 'new-company-role' });

      await service.createRole(
        {
          name: 'company_clerk',
          nameFa: 'کارمند شرکت',
          scopeType: RoleScope.GLOBAL,
          zoneId: 'zone-B',
        },
        companyActor,
      );

      expect(prisma.role.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          scopeType: RoleScope.COMPANY,
          zoneId: null,
          companyId: 'company-456',
        }),
      });
    });

    it('(g) updateRole ignores scope fields even if injected into the payload', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-z',
        name: 'zone_clerk',
        nameFa: 'کارمند زون',
        scopeType: RoleScope.ZONE,
        zoneId: 'zone-123',
        companyId: null,
        isSystem: false,
        permissions: [],
      });
      prisma.role.update.mockResolvedValue({ id: 'role-z', name: 'renamed_clerk' });

      await service.updateRole(
        'role-z',
        {
          name: 'renamed_clerk',
          scopeType: RoleScope.COMPANY,
          zoneId: 'zone-B',
          companyId: 'company-B',
        } as any,
        zoneActor,
      );

      expect(prisma.role.update).toHaveBeenCalledWith({
        where: { id: 'role-z' },
        data: { name: 'renamed_clerk' },
      });
    });

    it('(h) SUPER_ADMIN flows for read/update/delete/permissions on GLOBAL role still pass', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-global',
        name: 'global_role',
        nameFa: 'نقش سراسری',
        scopeType: RoleScope.GLOBAL,
        zoneId: null,
        companyId: null,
        isSystem: false,
        permissions: [],
      });
      const superActor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };

      await expect(service.getRoleById('role-global', superActor)).resolves.toMatchObject({
        id: 'role-global',
      });
      prisma.role.update.mockResolvedValue({ id: 'role-global' });
      await expect(
        service.updateRole('role-global', { name: 'renamed' }, superActor),
      ).resolves.toMatchObject({ id: 'role-global' });
      await expect(service.deleteRole('role-global', superActor)).resolves.not.toThrow();
      prisma.roleAssignment.findMany.mockResolvedValue([]);
      await expect(
        service.setRolePermissions('role-global', ['zone.visitors.view'], superActor),
      ).resolves.toEqual({ roleId: 'role-global', permissions: ['zone.visitors.view'] });
      // SUPER_ADMIN is exempt from the authority check — getUserPermissions not consulted
      expect(permissionsService.getUserPermissions).not.toHaveBeenCalled();
    });

    it('non-admin roles (e.g. ZONE_OPERATOR) may not use the service (ROLE_NOT_FOUND)', async () => {
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-any',
        name: 'some_role',
        nameFa: 'نقشی',
        scopeType: RoleScope.GLOBAL,
        zoneId: null,
        companyId: null,
        isSystem: false,
        permissions: [],
      });

      await expect(
        service.getRoleById('role-any', { userId: 'op-1', role: UserRole.ZONE_OPERATOR, zoneId: 'zone-123' }),
      ).rejects.toMatchObject({ code: 'ROLE_NOT_FOUND' });
    });
  });

  describe('unassignRole', () => {
    it('should remove role assignment, invalidate cache, and log audit', async () => {
      const actor: RoleActor = { userId: 'admin-1', role: UserRole.SUPER_ADMIN };
      prisma.role.findUnique.mockResolvedValue({
        id: 'role-1',
        name: 'finance_clerk',
        nameFa: 'کارشناس مالی',
        permissions: [],
      });
      prisma.roleAssignment.deleteMany.mockResolvedValue({ count: 1 });

      await service.unassignRole('role-1', 'target-user-1', actor);

      expect(prisma.roleAssignment.deleteMany).toHaveBeenCalledWith({
        where: { userId: 'target-user-1', roleId: 'role-1' },
      });
      expect(permissionsService.invalidateUserPermissions).toHaveBeenCalledWith('target-user-1');
      expect(audit.log).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'admin-1',
          targetId: 'target-user-1',
          action: 'ROLE_UNASSIGNED',
        }),
      );
    });
  });
});
