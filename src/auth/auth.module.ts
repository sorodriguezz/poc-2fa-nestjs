import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '@nestjs/config';
import { UsersModule } from '../users/users.module';
import { JwtStrategy } from './jwt.strategy';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TwoFaService } from './twofa/twofa.service';
import { TwoFaController } from './twofa/twofa.controller';

@Module({
  imports: [
    ConfigModule,
    UsersModule,
    PassportModule.register({ session: false }),
    JwtModule.register({}), // secrets se pasan en runtime
  ],
  providers: [AuthService, JwtStrategy, TwoFaService],
  controllers: [AuthController, TwoFaController],
})
export class AuthModule {}
