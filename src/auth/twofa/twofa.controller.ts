import {
  Body,
  Controller,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service';
import { TwoFaService } from './twofa.service';
import { UsersService } from '../../users/users.service';
import type { Request } from 'express';
import { randomBytes } from 'crypto';

class InitiateDto {
  issuer!: string;
  accountLabel!: string;
}

class EnableDto {
  code!: string;
}

class VerifyDto {
  code?: string;
  recoveryCode?: string;
} // admite recovery opcional

class RotateConfirmDto {
  code!: string;
}

interface TempTokenPayload {
  sub: string;
  email?: string;
  requiresMfa?: boolean;
  [key: string]: any;
}

@Controller('auth/2fa')
export class TwoFaController {
  constructor(
    private readonly twofa: TwoFaService,
    private readonly jwt: JwtService,
    private readonly cfg: ConfigService,
    private readonly auth: AuthService,
    private readonly users: UsersService,
  ) {}

  private async validateTempToken(req: Request): Promise<TempTokenPayload> {
    const raw = req?.headers?.authorization?.replace(/^Bearer\s+/i, '');

    if (!raw) throw new UnauthorizedException('Falta token temporal');

    try {
      return await this.jwt.verifyAsync<TempTokenPayload>(raw, {
        secret: this.cfg.get<string>('JWT_TEMP_SECRET')!,
      });
    } catch {
      throw new UnauthorizedException('Token temporal inválido o expirado');
    }
  }

  @Post('initiate')
  async initiate(@Req() req: Request, @Body() dto: InitiateDto) {
    const user = await this.validateTempToken(req);
    return this.twofa.initiate(user.sub, dto.issuer, dto.accountLabel);
  }

  @Post('enable')
  async enable(@Req() req: Request, @Body() dto: EnableDto) {
    const user = await this.validateTempToken(req);
    return this.twofa.enable(user.sub, dto.code);
  }

  @Post('rotate/confirm')
  async confirm(@Req() req: Request, @Body() dto: RotateConfirmDto) {
    const user = await this.validateTempToken(req);
    return this.twofa.enable(user.sub, dto.code); // activa nuevo (el viejo queda fuera)
  }

  @Post('recovery/regenerate')
  async regenerate(@Req() req: Request) {
    const user = await this.validateTempToken(req);

    const codes = Array.from(
      { length: 10 },
      () => randomBytes(5).toString('hex'), // 10 chars hex
    );
    await this.users.replaceUserRecoveryCodes(user.sub, codes);
    return { codes }; // Mostrar SOLO aquí. No se vuelven a exponer.
  }

  @Post('verify')
  async verify(@Req() req: Request, @Body() dto: VerifyDto) {
    const user = await this.validateTempToken(req);

    if (!user.requiresMfa) throw new UnauthorizedException('MFA no requerida');

    let ok = false;

    if (dto.code) {
      ok = await this.twofa.verifyForLogin(user.sub, dto.code);
    } else if (dto.recoveryCode) {
      ok = await this.users.consumeUserRecoveryCode(user.sub, dto.recoveryCode);
    }

    if (!ok) throw new UnauthorizedException('Código inválido');

    if (!user.email) throw new UnauthorizedException('Email missing');

    const access = this.auth.issueMfaAccessToken({
      id: user.sub,
      email: user.email,
    });

    return { access_token: access };
  }
}
