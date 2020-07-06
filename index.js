'use strict';
const app = module.app = module.parent.app;

const crypto = require('crypto');
const uid = require('uid-safe').sync;

var secret = 'secret';
var sessions = {};

var sign = function (val) {
    return val + '.' + crypto.createHmac('sha256', secret).update(val).digest('base64').replace(/\=+$/, '');
}

var unsign = function (val) {
    let str = val.slice(0, val.lastIndexOf('.'));
    let mac = sign(str, secret);

    return sha1(mac) == sha1(val) ? str : false;
}

var sha1 = function (str){
    return crypto.createHash('sha1').update(str).digest('hex');
}

module.exports = function (options) {
    if (options.redis) {
        var redis = require('redis').createClient(options.redis);
    }

    return function ($) {
        if (!$.cookies) {
            return $.return();
        }

        if (options.secret) {
            secret = options.secret;
        }

        let name = 'sid';
        let id = $.cookies.sid ? (unsign($.cookies.sid) || uid(24)) : uid(24);

        $.cookies.set('sid', sign(id), {
            expire: [1,0,0,0,0],
            secure: true
        });

        if (redis) {
            redis.get("sid." + id, function (err, data) {
                if (err) {
                    console.error(err);
                    throw err;
                }

                if (!data) {
                    $.session = {sid: id};
                } else {
                    $.session = JSON.parse(data);
                }

                $.session.save = function () {
                    let session = $.session;

                    delete session.save;
                    delete session.destroy;

                    redis.set("sid." + session.sid, JSON.stringify(session));
                };

                $.session.destroy = function () {
                    $.session = {};
                    redis.del("sid." + $.session.sid);
                    $.cookies.set('sid', '', {
                        expire: [-1,0,0,0,0],
                        secure: true
                    });
                };

                return $.return();
            });
        } else {
            if (!sessions[id]) {
                $.session = {sid: id};
            } else {
                $.session = sessions[id]
            }

            $.session.save = function () {
                let session = $.session;

                delete session.save;
                delete session.destroy;

                sessions[session.sid] = session;
            };

            $.session.destroy = function () {
                $.session = {};
                delete sessions[$.session.sid];
                $.cookies.set('sid', '', {
                    expire: [-1,0,0,0,0],
                    secure: true
                });
            };

            return $.return();
        }
    }
};