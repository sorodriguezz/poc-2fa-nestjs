import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

interface JwtPayload {
  sub?: string;
  email?: string;
  mfa?: boolean;
  amr?: string[];
  [key: string]: unknown;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly cfg: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: cfg.get<string>('JWT_ACCESS_SECRET')!,
      ignoreExpiration: false,
    });
  }

  validate(payload: JwtPayload) {
    if (!payload?.sub) throw new UnauthorizedException();
    return payload; // {sub,email,mfa,amr,...}
  }
}
