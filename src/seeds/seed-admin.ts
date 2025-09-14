// src/seeds/seed-admin.ts
import { DataSource, DeepPartial } from 'typeorm';
import * as dotenv from 'dotenv';
import * as argon2 from 'argon2';
import { RecoveryCode } from '../entities/recovery-code.entity';
import { User } from '../entities/user.entity';

dotenv.config();

const DB_PATH = process.env.DB_PATH!;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL!;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD!;

async function run() {
  const ds = new DataSource({
    type: 'sqlite',
    database: DB_PATH,
    entities: [User, RecoveryCode],
    synchronize: true, // para POC; en prod usar migraciones
    logging: false,
  });

  await ds.initialize();

  const userRepo = ds.getRepository(User);

  let admin = await userRepo.findOne({ where: { email: ADMIN_EMAIL } });
  if (admin) {
    console.log(`[seed] Admin ya existe: ${ADMIN_EMAIL}`);
  } else {
    const passwordHashArgon2id = await argon2.hash(ADMIN_PASSWORD);
    admin = userRepo.create({
      email: ADMIN_EMAIL,
      passwordHashArgon2id,
      isTwoFactorEnabled: false,
      twoFactorEncryptedSecretBase64: null,
      twoFactorEncryptionIvBase64: null,
      twoFactorEncryptionAuthTagBase64: null,
      pendingTwoFactorEncryptedSecretBase64: null,
      pendingTwoFactorEncryptionIvBase64: null,
      pendingTwoFactorEncryptionAuthTagBase64: null,
    } as DeepPartial<User>);
    await userRepo.save(admin);
    console.log(`[seed] Admin creado: ${ADMIN_EMAIL}`);
    console.log('[seed] Contraseña:', ADMIN_PASSWORD);
  }

  await ds.destroy();
}

run().catch((err) => {
  console.error('[seed] Error:', err);
  process.exit(1);
});
