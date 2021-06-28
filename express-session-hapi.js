'use strict';

var Boom = require('boom');
var Hoek = require('hoek');
var Joi = require('joi');
var Redis = require('ioredis');
var signature = require('cookie-signature');

var internals = {};

module.exports = {
  pkg: require('./package.json'),
  register: (server, options) => {
    server.auth.scheme('express-session-hapi', internals.implementation);
  }
};

internals.schema = Joi.object({
  clearInvalid: Joi.boolean().default(false),
  cookieName: Joi.string(),
  cookieValuePrefix: Joi.string().default('s:'),
  redirectTo: Joi.string().allow(false),
  redis: Joi.object().keys({
    host: Joi.string(),
    port: Joi.number().default(6379),
    password: Joi.string(),
    clusterEnabled: Joi.boolean().default(false),
  }),
  secret: Joi.string(),
  sessionIDPrefix: Joi.string().default('sess:'),
  userProp: Joi.string().default('user'),
}).required();

internals.implementation = function (server, options) {
  var results = Joi.validate(options, internals.schema);
  Hoek.assert(!results.error, results.error);

  var settings = results.value;

  if (typeof settings.appendNext === 'boolean') {
    settings.appendNext = (settings.appendNext ? 'next' : '');
  }

  var redisClient;

  if (settings.redis.clusterEnabled) {
    var nodes = [{ port: settings.redis.port, host: settings.redis.host }];
    var options = {};

    if (settings.redis.password) {
      options = {
        redisOptions: {
          password: settings.redis.password,
        },
      };
    }
    
    redisClient = new Redis.Cluster(nodes, options);
  } else {
    var options = {
      port: settings.redis.port, 
      host: settings.redis.host
    };

    if (settings.redis.password) {
      options.password = settings.redis.password;
    }

    redisClient = new Redis({
      port: settings.redis.port, 
      host: settings.redis.host,
    });
  }

  function decodeCookieValue(val) {
    val = decodeURIComponent(val).trim();

    // quoted values
    if ('"' === val[0]) {
      val = val.slice(1, -1);
    }

    return val;
  }

  var scheme = {
    authenticate: async function (request, h) {
      var validate = async function () {
        var rawCookieValue = request.state[settings.cookieName];

        if (!rawCookieValue) {
          return unauthenticated(Boom.unauthorized(null, 'cookie'));
        }

        rawCookieValue = decodeCookieValue(rawCookieValue);

        var sessionID;

        if (rawCookieValue.substr(0, 2) === settings.cookieValuePrefix) {
          sessionID = signature.unsign(rawCookieValue.slice(2), settings.secret);

          if (sessionID === false) {
            // cookie signature invalid
            sessionID = undefined;

            if (settings.clearInvalid) {
              h.unstate(settings.cookieName);
            }

            return unauthenticated(Boom.unauthorized('Invalid cookie'));
          }
        } else {
          return unauthenticated(Boom.unauthorized(null, 'cookie'));
        }

        var promisifyGet = function (key) {
          return new Promise((resolve, reject) => {
            redisClient.get(key, (err, data) => {
              if (err) {
                return reject(err);
              }

              return resolve(data);
            });
          });
        };

        try {
          let data = await promisifyGet(settings.sessionIDPrefix + sessionID);

          if (!data) {
            return unauthenticated(Boom.unauthorized(null, 'cookie'));
          }

          data = JSON.parse(data.toString());

          if (!data[settings.userProp]) {
            return unauthenticated(Boom.unauthorized(null, 'cookie'));
          }

          var user = data[settings.userProp];

          if (user.name === 'Anonymous') {
            return unauthenticated(Boom.unauthorized(null, 'cookie'));
          }

          return h.authenticated({
            artifacts: data,
            credentials: data,
          });
        } catch (err) {
          return unauthenticated(Boom.unauthorized('Server error when checking authorizaiton'));
        }
      };

      var unauthenticated = function (err, result) {
        var redirectTo = settings.redirectTo;

        if (!redirectTo) {
          return h.unauthenticated(err);
        }

        var uri = redirectTo;

        if (settings.appendNext) {
          if (uri.indexOf('?') !== -1) {
            uri += '&';
          }
          else {
            uri += '?';
          }

          uri += settings.appendNext + '=' + encodeURIComponent(request.url.path);
        }

        return h.response('Please refresh page after login success~').takeover();
      };

      var validateResult = await validate();

      return validateResult;
    }
  };

  return scheme;
};
