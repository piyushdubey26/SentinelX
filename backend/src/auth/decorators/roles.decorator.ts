import { SetMetadata } from '@nestjs/common';
import { RoleType } from '../../users/entities/role.entity';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: RoleType[]) => SetMetadata(ROLES_KEY, roles);
