use std::env;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref MONGODB_URI: String = env::var("MONGODB_URI").expect("MONGODB_URI must be set");
    pub static ref MONGODB_DATABASE: String =
        env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
    pub static ref JWT_SECRET: String = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    pub static ref SALT: String = env::var("SALT").expect("SALT must be set");
    pub static ref HCAPTCHA_SECRET: String = env::var("HCAPTCHA_SECRET").expect("HCAPTCHA_SECRET must be set");
}
