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

    const temporaryToken = this.authService.issueTemporaryToken({
      id: user.id,
      email: user.email,
      twoFactorEnabled: user.isTwoFactorEnabled,
    });

    return {
      access_token: temporaryToken,
      requiresMfa: !!user.isTwoFactorEnabled,
    };
  }
}
