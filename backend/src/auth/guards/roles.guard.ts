import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { RoleType } from '../../users/entities/role.entity';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<RoleType[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    if (!user || !user.role) {
      throw new ForbiddenException('Access denied. No authenticated role detected.');
    }

    const userRole = typeof user.role === 'string' ? user.role : user.role.name;
    const hasRole = requiredRoles.includes(userRole as RoleType);

    if (!hasRole) {
      throw new ForbiddenException(
        `Access denied. Role [${userRole}] does not have permission to access this resource. Required: [${requiredRoles.join(', ')}]`,
      );
    }

    return true;
  }
}
