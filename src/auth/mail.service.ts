import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';

@Injectable()
export class MailService {
  private readonly resend: Resend;
  constructor(private readonly configService: ConfigService) {
    this.resend = new Resend(this.configService.getOrThrow<string>('RESEND_API_KEY'));
  }

  async sendPasswordResetEmail(to: string, resetUrl: string): Promise<void> {
    const from = this.configService.getOrThrow<string>('EMAIL_FROM');

    await this.resend.emails.send({
      from,
      to,
      subject: 'Reset your password',
      html: `
        <p>We received a request to reset your password.</p>
        <p>Please click the following link to reset your password:</p>
        <a href="${resetUrl}">Click here to reset your password</a>
        <p>This link expires in 15 minutes. If you didn't request this, you can ignore this email.</p>
      `,
    });
  }
}
