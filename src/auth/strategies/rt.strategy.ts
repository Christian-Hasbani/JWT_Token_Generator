import { ConfigService } from '@nestjs/config';
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy,'jwt-refresh'){
    constructor(private configService:ConfigService){
        const secretKey = configService.getOrThrow<string>("RT_SECRET");
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: secretKey,
            passReqToCallback: true,
        });
    }

    validate(req: Request,payload:any){
        const refreshToken = req.get('authorization')?.replace('Bearer','').trim();
        return {
            ...payload,
            refreshToken
        };
    }
}