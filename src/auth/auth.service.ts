import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { User } from '../entities/user.entity';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
  ) {}

  async validateUserCredentials(
    email: string,
    password: string,
  ): Promise<User> {
    const userRecord = await this.usersService.findUserByEmail(email);

    if (
      !userRecord ||
      !(await argon2.verify(userRecord.passwordHashArgon2id, password))
    ) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    return userRecord;
  }

  issueTemporaryToken(user: {
    id: string;
    email: string;
    twoFactorEnabled: boolean;
  }): string {
    const tokenPayload = {
      sub: user.id,
      email: user.email,
      requiresMfa: !!user.twoFactorEnabled,
      amr: ['pwd'],
    };
    return this.jwtService.sign(tokenPayload, {
      secret: this.configService.get<string>('JWT_TEMP_SECRET')!,
      expiresIn: this.configService.get<string>('JWT_TEMP_TTL')!,
    });
  }

  issueMfaAccessToken(user: { id: string; email: string }): string {
    const tokenPayload = {
      sub: user.id,
      email: user.email,
      amr: ['pwd', 'mfa'],
      mfa: true,
    };
    return this.jwtService.sign(tokenPayload, {
      secret: this.configService.get<string>('JWT_ACCESS_SECRET')!,
      expiresIn: this.configService.get<string>('JWT_ACCESS_TTL')!,
    });
  }
}
