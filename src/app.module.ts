import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { envsConfig } from './config';
import { User } from './entities/user.entity';
import { RecoveryCode } from './entities/recovery-code.entity';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: envsConfig,
    }),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => ({
        type: 'sqlite',
        database: cfg.get<string>('DB_PATH'),
        entities: [User, RecoveryCode],
        synchronize: true,
      }),
    }),
    UsersModule,
    AuthModule,
  ],
})
export class AppModule {}
