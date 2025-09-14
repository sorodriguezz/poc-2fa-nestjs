import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export interface EncryptedPayload {
  ciphertextBase64: string;
  initialVectorBase64: string;
  authTagBase64: string;
}

@Injectable()
export class EncryptionService {
  private encryptionKey: Buffer;

  constructor(private readonly configService: ConfigService) {
    const keyBase64 = configService.get<string>('TWOFA_ENC_KEY_BASE64')!;
    this.encryptionKey = Buffer.from(keyBase64, 'base64');
  }

  encrypt(plaintext: string): EncryptedPayload {
    const initialVector = randomBytes(12);
    const cipher = createCipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      initialVector,
    );
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    return {
      ciphertextBase64: ciphertext.toString('base64'),
      initialVectorBase64: initialVector.toString('base64'),
      authTagBase64: authTag.toString('base64'),
    };
  }

  decrypt(
    ciphertextBase64: string,
    initialVectorBase64: string,
    authTagBase64: string,
  ): string {
    const initialVector = Buffer.from(initialVectorBase64, 'base64');
    const ciphertext = Buffer.from(ciphertextBase64, 'base64');
    const authTag = Buffer.from(authTagBase64, 'base64');

    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      initialVector,
    );

    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return plaintext.toString('utf8');
  }
}
