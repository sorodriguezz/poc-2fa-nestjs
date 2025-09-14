import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

class LoginRequestDto {
  email: string;
  password: string;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(@Body() credentials: LoginRequestDto) {
    const user = await this.authService.validateUserCredentials(
      credentials.email,
      credentials.password,
    );

    if (!user.isTwoFactorEnabled) {
      // Si no requiere MFA, entregar el JWT de acceso principal directamente
      const accessToken = this.authService.issueMfaAccessToken({
        id: user.id,
        email: user.email,
      });

      return {
        access_token: accessToken,
        requiresMfa: false,
      };
    }

    // Si requiere MFA, entregar el token temporal
    const temporaryToken = this.authService.issueTemporaryToken({
      id: user.id,
      email: user.email,
      twoFactorEnabled: user.isTwoFactorEnabled,
    });

    return {
      access_token: temporaryToken,
      requiresMfa: true,
    };
  }
}
