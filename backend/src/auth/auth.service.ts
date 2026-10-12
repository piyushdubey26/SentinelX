import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { AuditService } from '../audit/audit.service';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly auditService: AuditService,
  ) {}

  async login(dto: LoginDto, ipAddress: string) {
    const user = await this.usersService.findByEmail(dto.email);

    if (!user) {
      await this.auditService.logAction({
        action: 'USER_LOGIN_FAILED',
        resourceType: 'AUTH',
        resourceId: dto.email,
        ipAddress,
        details: { reason: 'User not found' },
      });
      throw new UnauthorizedException('Invalid email or password');
    }

    if (!user.isActive) {
      await this.auditService.logAction({
        userId: user.id,
        action: 'USER_LOGIN_FAILED',
        resourceType: 'AUTH',
        resourceId: user.id,
        ipAddress,
        details: { reason: 'Account deactivated' },
      });
      throw new UnauthorizedException('Account has been deactivated');
    }

    const isMatch = await bcrypt.compare(dto.password, user.passwordHash);
    if (!isMatch) {
      await this.auditService.logAction({
        userId: user.id,
        action: 'USER_LOGIN_FAILED',
        resourceType: 'AUTH',
        resourceId: user.id,
        ipAddress,
        details: { reason: 'Invalid password' },
      });
      throw new UnauthorizedException('Invalid email or password');
    }

    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role.name,
      permissions: user.role.permissions,
    };

    const accessToken = this.jwtService.sign(payload);

    await this.auditService.logAction({
      userId: user.id,
      action: 'USER_LOGIN_SUCCESS',
      resourceType: 'AUTH',
      resourceId: user.id,
      ipAddress,
      details: { role: user.role.name },
    });

    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn: 3600,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role.name,
        permissions: user.role.permissions,
      },
    };
  }

  async logout(userId: string, ipAddress: string) {
    await this.auditService.logAction({
      userId,
      action: 'USER_LOGOUT',
      resourceType: 'AUTH',
      resourceId: userId,
      ipAddress,
      details: { outcome: 'SUCCESS' },
    });
    return { message: 'Logged out successfully' };
  }
}
