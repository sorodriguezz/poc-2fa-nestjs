import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index({ unique: true })
  @Column()
  email: string;

  @Column() // Argon2id hashed password
  passwordHashArgon2id: string;

  @Column({ default: false })
  isTwoFactorEnabled: boolean;

  // TOTP secret encrypted with AES-GCM
  @Column({ type: 'text', nullable: true }) // base64(ciphertext)
  twoFactorEncryptedSecretBase64: string | null;

  @Column({ type: 'text', nullable: true }) // base64(iv)
  twoFactorEncryptionIvBase64: string | null;

  @Column({ type: 'text', nullable: true }) // base64(authTag)
  twoFactorEncryptionAuthTagBase64: string | null;

  // Prevención de reutilización de códigos TOTP
  @Column({ type: 'varchar', nullable: true })
  lastTotpCode: string | null;

  @Column({ type: 'bigint', nullable: true })
  lastTotpTimestamp: number | null;

  // Pending activation (new TOTP secret not yet verified)
  @Column({ type: 'text', nullable: true })
  pendingTwoFactorEncryptedSecretBase64: string | null;

  @Column({ type: 'text', nullable: true })
  pendingTwoFactorEncryptionIvBase64: string | null;

  @Column({ type: 'text', nullable: true })
  pendingTwoFactorEncryptionAuthTagBase64: string | null;
}
