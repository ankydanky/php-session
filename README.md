# php-session
PHPSession is a MySQL session storage class. It encrypts all data using openssl.

Usage:

require_once("class.session.php");
$sess = new PHPSession($PDO_INSTANCE);
$sess->start_session();
