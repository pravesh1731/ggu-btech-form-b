const bcrypt = require('bcrypt');
const password = 'admin123';

bcrypt.hash(password, 12, (err, hash) => {
  console.log('ADMIN_PASSWORD_HASH=' + hash);
});
