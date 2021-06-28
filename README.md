# express-session-hapi

A `hapi` plugin to read session data from Redis saved previously using `express-session`.

## Usage

```javascript
const expressSessionHapi = require('express-session-hapi');

// `server` is a hapi server.
const config = server.config();

// Required options.
const options = {
  cookieName: config.get('cookieName'),
  redirectTo: config.get('redirectTo'),
  redis: config.get(`redis'),
  secret: config.get('secret'),
};

server.register(expressSessionHapi, function (error) {
  server.auth.strategy('session', 'cookie', 'required', options);
});
```

## Options

```javascript
{
	// If true, any authentication cookie that fails validation will be marked as expired in the response and cleared.
  clearInvalid: Joi.boolean().default(false),
  // The cookie name.
  cookieName: Joi.string(),
  // The value used by express-session to prefix the cookie value.
  cookieValuePrefix: Joi.string().default('s:'),
  // Optional login URI to redirect unauthenticated requests to.
  redirectTo: Joi.string().allow(false),
  // The connection information for Redis
  redis: Joi.object().keys({
    host: Joi.string(),
    port: Joi.number().default(6379),
    password: Joi.string(),
  }),
  // A secret/password to decrypt the cookie.
  secret: Joi.string(),
  // The value used by express-session to prefix the Redis key.
  sessionIDPrefix: Joi.string().default('sess:'),
  // The property in the session data (JSON) retrieved from Redis 
  // that holds the user info. `express-session` has an option to 
  // save even empty, unauthorized user session info to Redis. Such
  // session will lack this `userProp` field.
  userProp: Joi.string().default('user'),
}
```

## License

The [MIT](https://github.com/kadishmal/express-session-hapi/blob/master/LICENSE) License (MIT)

Copyright (c) 2016 Esen Sagynov
