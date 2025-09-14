import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';

interface MfaUser {
  mfa?: boolean;
  amr?: string[];
}

@Injectable()
export class MfaGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request & { user?: MfaUser }>();
    const user = req.user;

    if (!user) throw new UnauthorizedException();

    if (
      user.mfa === true ||
      (Array.isArray(user.amr) && user.amr.includes('mfa'))
    ) {
      return true;
    }

    throw new UnauthorizedException('Acceso requiere MFA');
  }
}
