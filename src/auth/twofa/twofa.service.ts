import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../../users/users.service';
import { authenticator } from 'otplib';
import { toDataURL } from 'qrcode';
import {
  EncryptedPayload,
  EncryptionService,
} from '../../crypto/encryption.service';

@Injectable()
export class TwoFaService {
  constructor(
    private readonly users: UsersService,
    private readonly crypto: EncryptionService,
  ) {
    authenticator.options = { step: 30, digits: 6, window: 1 };
  }

  private encryptSecret(secret: string): EncryptedPayload {
    return this.crypto.encrypt(secret); // {ciphertextB64,ivB64,tagB64}
  }

  private decryptSecret(encrypted: {
    ciphertextB64: string;
    ivB64: string;
    tagB64: string;
  }) {
    return this.crypto.decrypt(
      encrypted.ciphertextB64,
      encrypted.ivB64,
      encrypted.tagB64,
    );
  }

  async initiate(userId: string, issuerName: string, accountName: string) {
    const user = await this.users.findUserById(userId);

    if (!user) throw new UnauthorizedException();

    const secret = authenticator.generateSecret(); // base32

    const otpauthUrl = authenticator.keyuri(accountName, issuerName, secret);

    const pendingEncryptedSecret = this.encryptSecret(secret);

    await this.users.setPendingTwoFactorSecret(user, pendingEncryptedSecret);

    const qrCodeDataUrl = await toDataURL(otpauthUrl);

    return { otpauthUrl, qr: qrCodeDataUrl };
  }

  async enable(userId: string, verificationCode: string) {
    const user = await this.users.findUserById(userId);

    if (!user?.pendingTwoFactorEncryptedSecretBase64) {
      throw new UnauthorizedException('No hay secreto pendiente');
    }

    const decryptedSecret = this.decryptSecret({
      ciphertextB64: user.pendingTwoFactorEncryptedSecretBase64,
      ivB64: user.pendingTwoFactorEncryptionIvBase64!,
      tagB64: user.pendingTwoFactorEncryptionAuthTagBase64!,
    });

    const isValid = authenticator.verify({
      token: verificationCode,
      secret: decryptedSecret,
    });

    if (!isValid) throw new UnauthorizedException('Código 2FA inválido');

    const encryptedSecret = this.encryptSecret(decryptedSecret);
    await this.users.enableTwoFactorAuthentication(user, encryptedSecret);

    return { enabled: true };
  }

  async verifyForLogin(
    userId: string,
    verificationCode: string,
  ): Promise<boolean> {
    const user = await this.users.findUserById(userId);

    if (!user?.isTwoFactorEnabled || !user.twoFactorEncryptedSecretBase64) {
      return false;
    }

    const decryptedSecret = this.decryptSecret({
      ciphertextB64: user.twoFactorEncryptedSecretBase64,
      ivB64: user.twoFactorEncryptionIvBase64!,
      tagB64: user.twoFactorEncryptionAuthTagBase64!,
    });

    // Calcular el timestamp de la ventana TOTP actual
    const step = 30; // segundos
    const now = Math.floor(Date.now() / 1000);
    const windowTimestamp = Math.floor(now / step) * step;

    // Verificar si el código ya fue usado en esta ventana
    if (
      user.lastTotpCode === verificationCode &&
      user.lastTotpTimestamp === windowTimestamp
    ) {
      return false; // Código ya usado en esta ventana
    }

    const isValid = authenticator.verify({
      token: verificationCode,
      secret: decryptedSecret,
    });

    if (isValid) {
      // Guardar el código y timestamp de la ventana actual
      await this.users.setLastTotpCode(
        user.id,
        verificationCode,
        windowTimestamp,
      );
    }

    return isValid;
  }
}
