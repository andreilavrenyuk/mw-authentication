
const _ = require('underscore');
const AppError = require('app-utils').AppError;
const prequire = require('parent-require');

const mongoose = prequire('mongoose');


const User = mongoose.model('User');

module.exports = {

  authorize(ctx, next) {
    const apikey = ctx.request.body.apikey || ctx.request.headers['x-api-key'];
    if (!apikey) {
      throw new AppError(_.isUndefined(apikey) ? 'Request hasn\'t apikey' : 'Apikey is not valid');
    }
    return User.findOne({ apikey }).then((user) => {
      if (!user) {
        throw new AppError(401);
      }
      ctx._user = user;
      return next();
    }).catch((err) => {
      throw err;
    });
  },

  authenticate(ctx, next) {
    //noinspection JSUnresolvedVariable
    const token = ctx.request.headers['x-access-token'];
    if (!token) {
      throw new AppError('Request hasn\'t access token', 401);
    }
    try {
      //noinspection JSUnresolvedFunction
      return User.decodeToken(token).then((decoded) => {
        //noinspection JSUnresolvedFunction
        return User.findById(decoded.iss).then((doc) => {
          if (!doc) {
            throw new AppError(401);
          }
          ctx._user = doc;
          return next();
        }).catch((err) => {
          throw err;
        });
      }).catch(() => {
        throw new AppError('Access token has expired', 401);
      });
    } catch (err) {
      throw err;
    }
  },

  tryAauthenticate: (ctx, next) => {
    //noinspection JSUnresolvedVariable
    const token = ctx.request.headers['x-access-token'];
    if (!token) {
      throw new AppError('Request hasn\'t access token', 401);
    }
    try {
      //noinspection JSUnresolvedFunction
      return User.decodeToken(token).then((decoded) => {
        //noinspection JSUnresolvedFunction
        return User.findById(decoded.iss).then((doc) => {
          if (doc) {
            ctx._user = doc;
          }
          return next();
        }).catch((err) => {
          throw err;
        });
      }).catch(() => {
        throw new AppError('Access token has expired', 401);
      });
    } catch (err) {
      throw err;
    }
  },

  requireRoles(roles) {
    return (ctx, next) => {
      if (ctx._user && _.intersection(ctx._user.roles || [], roles).length > 0) {
        return next();
      }
      throw new AppError(401);
    };
  }
};
