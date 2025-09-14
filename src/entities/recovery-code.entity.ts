import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';

@Entity('recovery_codes')
export class RecoveryCode {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index()
  @Column()
  userId: string;

  // Guardamos SOLO hash (argon2) del código
  @Column()
  codeHash: string;

  @Column({ type: 'datetime', nullable: true })
  usedAt: Date | null;
}
