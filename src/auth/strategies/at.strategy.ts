import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy,'jwt'){
    constructor(private configService:ConfigService){
        const secretKey = configService.getOrThrow<string>("AT_SECRET");
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: secretKey,
        });
    }

    validate(payload:any){
        return payload;
    }
}