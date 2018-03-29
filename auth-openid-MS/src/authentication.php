<?php

require_once(INCLUDE_DIR.'class.plugin.php');
require_once('config.php');

class OpenIDAuthMS extends Plugin {
    var $config_class = "OpenIDAuthMSPluginConfig";

    function bootstrap() {
        $config = $this->getConfig();
        $clientAccess = $config->get('PLUGIN_ENABLED_CLIENT');
        $staffAccess = $config->get('PLUGIN_ENABLED_STAFF');
        if ($staffAccess) {
          require_once('openid_ms.php');
            StaffAuthenticationBackend::register(
                new MicrosoftOpenIDStaffAuthBackend($this->getConfig()));
        }
        if ($clientAccess) {
          require_once('openid_ms.php');
            UserAuthenticationBackend::register(
                new MicrosoftOpenIDClientAuthBackend($this->getConfig()));
        }
    }
}

require_once(INCLUDE_DIR.'UniversalClassLoader.php');
use Symfony\Component\ClassLoader\UniversalClassLoader_osTicket;
$loader = new UniversalClassLoader_osTicket();
$loader->registerNamespaceFallbacks(array(
    dirname(__file__).'/lib'));
$loader->register();