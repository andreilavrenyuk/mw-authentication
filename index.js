
const _ = require('underscore');
const AppError = require('app-utils').AppError;
const mongoose = module.parent.require('mongoose');


module.exports = function Auth(model) {

  this.user = mongoose.model(model);
  
  this.authorize = (ctx, next) => {
    const apikey = ctx.request.body.apikey || ctx.request.headers['x-api-key'];
    if (!apikey) {
      throw new AppError(_.isUndefined(apikey) ? 'Request hasn\'t apikey' : 'Apikey is not valid', 401);
    }
    return this.user.findOne({ apikey }).then((user) => {
      if (!user) {
        throw new AppError(401);
      }
      ctx._user = user;
      return next();
    });
  };

  this.authenticate = (ctx, next) => {
    //noinspection JSUnresolvedVariable
    const token = ctx.request.headers['x-access-token'];
    if (!token) {
      throw new AppError('Request hasn\'t access token', 401);
    }
    //noinspection JSUnresolvedFunction
    return this.user.decodeToken(token).then((decoded) => {
      //noinspection JSUnresolvedFunction
      return this.user.findById(decoded.iss).then((doc) => {
        if (!doc) {
          throw new AppError(401);
        }
        ctx._user = doc;
        return next();
      });
    }, () => {
      throw new AppError('Access token has expired', 401);
    });
  };

  this.tryAauthenticate = (ctx, next) => {
    //noinspection JSUnresolvedVariable
    const token = ctx.request.headers['x-access-token'];
    if (!token) {
      throw new AppError('Request hasn\'t access token', 401);
    }
    //noinspection JSUnresolvedFunction
    return this.user.decodeToken(token).then((decoded) => {
      //noinspection JSUnresolvedFunction
      return this.user.findById(decoded.iss).then((doc) => {
        if (doc) {
          ctx._user = doc;
        }
        return next();
      });
    }, () => {
      throw new AppError('Access token has expired', 401);
    });
  };

  this.requireRoles = (roles) => {
    return (ctx, next) => {
      if (ctx._user && _.intersection(ctx._user.roles || [], roles).length > 0) {
        return next();
      }
      throw new AppError(403);
    };
  }
};
