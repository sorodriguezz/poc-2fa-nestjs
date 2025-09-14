import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import * as argon2 from 'argon2';
import { User } from '../entities/user.entity';
import { RecoveryCode } from '../entities/recovery-code.entity';
import { EncryptedPayload } from 'src/crypto/encryption.service';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
    @InjectRepository(RecoveryCode)
    private readonly recoveryCodeRepository: Repository<RecoveryCode>,
  ) {}

  findUserByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  findUserById(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }

  async createUserWithPassword(
    email: string,
    rawPassword: string,
  ): Promise<User> {
    const passwordHash = await argon2.hash(rawPassword);
    return this.userRepository.save({ email, passwordHash });
  }

  async setPendingTwoFactorSecret(
    user: User,
    encrypted: EncryptedPayload,
  ): Promise<void> {
    const newUser = {
      ...user,
      pendingTwoFactorEncryptedSecretBase64: encrypted.ciphertextBase64,
      pendingTwoFactorEncryptionIvBase64: encrypted.initialVectorBase64,
      pendingTwoFactorEncryptionAuthTagBase64: encrypted.authTagBase64,
    };

    await this.userRepository.save(newUser);
  }

  async enableTwoFactorAuthentication(user: User, encrypted: EncryptedPayload) {
    const newUser = {
      ...user,
      isTwoFactorEnabled: true,
      twoFactorEncryptedSecretBase64: encrypted.ciphertextBase64,
      twoFactorEncryptionIvBase64: encrypted.initialVectorBase64,
      twoFactorEncryptionAuthTagBase64: encrypted.authTagBase64,
      pendingTwoFactorEncryptedSecretBase64: null,
      pendingTwoFactorEncryptionIvBase64: null,
      pendingTwoFactorEncryptionAuthTagBase64: null,
      lastTotpCode: null,
      lastTotpTimestamp: null,
    };

    await this.userRepository.save(newUser);
  }

  async setLastTotpCode(userId: string, code: string, timestamp: number) {
    await this.userRepository.update(userId, {
      lastTotpCode: code,
      lastTotpTimestamp: timestamp,
    });
  }

  async replaceUserRecoveryCodes(userId: string, plainRecoveryCodes: string[]) {
    await this.recoveryCodeRepository.delete({ userId });

    const newRecoveryCodeRows = await Promise.all(
      plainRecoveryCodes.map(async (plainCode) =>
        this.recoveryCodeRepository.create({
          userId,
          codeHash: await argon2.hash(plainCode),
          usedAt: null,
        }),
      ),
    );

    await this.recoveryCodeRepository.save(newRecoveryCodeRows);
  }

  async consumeUserRecoveryCode(userId: string, plainCode: string) {
    const unusedRecoveryCodes = await this.recoveryCodeRepository.find({
      where: { userId, usedAt: IsNull() },
    });

    const matchedRecoveryCode = await (async () => {
      for (const rc of unusedRecoveryCodes)
        if (await argon2.verify(rc.codeHash, plainCode)) return rc;
      return null;
    })();

    if (!matchedRecoveryCode) return false;
    matchedRecoveryCode.usedAt = new Date();
    await this.recoveryCodeRepository.save(matchedRecoveryCode);
    return true;
  }
}
