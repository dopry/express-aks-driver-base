///////////////////////////////////
// Generic Driver Implementation //
///////////////////////////////////

/**
 * Initalize a new Driver Object
 */
function Driver() {
    var kdb = this;
    return this;
}


Driver.prototype._validateEmail = function(email) {
    var pattern = /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))$/i;
    if(email.match(pattern)) {
        return true;
    }
    return false;
};

Driver.prototype._validateKey = function(key) {
    if (key.indexOf('-----BEGIN PGP PUBLIC KEY BLOCK-----') < 0) {
        return false;
    }
    return true;
    // TODO: use a pgp lib to attempt to parse the key.
};

/**
 * Find a single key from the email uid
 * @param  {String}   email Email uid to retrieve a key for
 * @param  {Function} callback Function to evaluate with the results of the find
 */
Driver.prototype.findOne = function(email, callback) {
    if (!email) {
        callback('email missing')
        return;
    }
    if (!this._validateEmail(email)) {
        callback('email malformed')
        return;
    }

    var parts = email.split('@'),
        domain = parts[1],
        user = parts[0];

    callback(null, {
        email: email,
        user: user,
        domain: domain,
        keytext: null
    });
};



 /**
 * Find all the keys for this server
 * @param  {String}   domain Optional domain in which to search for keys
 * @param  {Function} callback Function to evaluate with the results of the find
 */
Driver.prototype.find = function(domain, callback) {
    if (!domain) {
        callback('domain missing');
        return;
    }
    callback(null, []);
};


/**
 * Add a key to the database
 * @param {String}   email Email to associate with the key
 * @param {String}   keytext ASCII-armored keytext including headers
 * @param {Function} callback Function to evaluate with an error or the added key on success
 */
Driver.prototype.add = function(email, keytext, callback) {
    if (!email) {
        callback('email missing');
        return;
    }
    if (!this._validateEmail(email)) {
        callback('email malformed')
        return;
    }
    if (!keytext) {
        callback('keytext missing');
        return;
    }
    if (!this._validateKey(keytext)) {
        callback('keytext malformed');
        return;
    }
    var parts = email.split('@'),
        domain = parts[1],
        user = parts[0];

    callback(null, {
        email: email,
        user: user,
        domain: domain,
        keytext: keytext
    });
};



/**
 * Export the Driver object
 */

module.exports = Driver;