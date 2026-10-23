import { Global, Module } from '@nestjs/common';
import { AuditService } from './services/audit.service';
import { ScopeService } from './services/scope.service';
import { PermissionsService } from '../modules/permissions/permissions.service';
import { PermissionsGuard } from './guards/permissions.guard';

@Global()
@Module({
  providers: [AuditService, ScopeService, PermissionsService, PermissionsGuard],
  exports: [AuditService, ScopeService, PermissionsService, PermissionsGuard],
})
export class CommonModule {}
