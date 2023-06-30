export interface JwtPayload {
  id: string;
  status: boolean;
  role: number;
}

export enum allowedGrants {
  client_credentials = 'client_credentials',
}

export enum scopes {
  profile = 'profile',
  user_info = 'user_info',
}

export class tokenPayload {
  sub: string;
  scope: scopes;
  client_id: string;
  iat: number;
  exp: number;
}

export class userToken {
  id: string;
  status: boolean;
  role: number;
  iat: number;
  exp: number;
}

export class userInfo {
  email: string;
  name: string;
  gender: string;
  birth_day: Date;
}

export class patient {
  _id: string;
  firstName: string;
  lastName: string;
  fullName: string;
  dni: string;
  dniWithoutDv: number;
  birthDay: Date;
  password: string;
  position: string;
  email: string;
  gender: string;
  phone: number;
  address: object[];
  company: object;
  branchOfficeId: object;
  termsAndConditionsCheck: boolean;
  status: boolean;
  createdAt: Date;
  updatedAt: Date;
  __v: number;
  healthForecast: string;
}
