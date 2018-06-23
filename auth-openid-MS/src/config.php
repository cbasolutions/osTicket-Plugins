<?php

require_once INCLUDE_DIR . 'class.plugin.php';

class OpenIDAuthMSPluginConfig extends PluginConfig {

  // Provide compatibility function for versions of osTicket prior to
  // translation support (v1.9.4)
  function translate() {
    if (!method_exists('Plugin', 'translate')) {
      return array(
        function($x) { return $x; },
        function($x, $y, $n) { return $n != 1 ? $y : $x; },
      );
    }
    return Plugin::translate('auth-openid-MS');
  }

  function getOptions() {
    list($__, $_N) = self::translate();
    return array(
      'MSAUTH' => new SectionBreakField(array(
        'label' => $__('Microsoft OpenID Provider Configuration'),
      )),
      'CLIENT_ID' => new TextboxField(array(
        'label' => $__('Client ID'),
        'required'=>true,
        'configuration' => array('size'=>60, 'length'=>100),
      )),
      'CLIENT_SECRET' => new TextboxField(array(
        'label' => $__('Client Secret'),
        'required'=>true,
        'configuration' => array('size'=>60, 'length'=>100),
      )),
      /*'LOGIN_LOGO' => new TextboxField(array(
        'label' => $__('URL to login logo - Not yet implemented'),
        'configuration' => array('size'=>60, 'length'=>250),
        'value'=>'https://docs.microsoft.com/en-us/azure/active-directory/develop/media/active-directory-branding-guidelines/sign-in-with-microsoft-light.png'
      )),*/
      'AUTHORITY_URL' => new TextboxField(array(
        'label' => $__('Authority URL'),
        'required'=>true,
        'hint' => $__('Base URL for authorization. E.g., https://login.microsoftonline.com/common'),
        'configuration' => array('size'=>60, 'length'=>100),
      )),
      'AUTHORIZE_ENDPOINT' => new TextboxField(array(
        'label' => $__('Authorization Endpoint'),
        'required'=>true,
        'hint' => $__('This will form the rest of the authorization URL. E.g., /oauth2/v2.0/authorize'),
        'configuration' => array('size'=>60, 'length'=>100),
      )),
      /*'TOKEN_ENDPOINT' => new TextboxField(array(
        'label' => $__('Token Endpoint'),
        'required'=>true,
        'hint' => $__('This will form the rest of the token URL. E.g., /oauth2/v2.0/token'),
        'configuration' => array('size'=>60, 'length'=>100),
      )),
      'RESOURCE_ID' => new TextboxField(array(
        'label' => $__('Resource URL'),
        'required'=>true,
        'hint' => $__('This is the base URL for the service holding the user data.. E.g., https://graph.microsoft.com'),
        'configuration' => array('size'=>60, 'length'=>100),
      )),
      'RESOURCE_ENDPOINT' => new TextboxField(array(
        'label' => $__('Resource Endpoint'),
        'required'=>true,
        'hint' => $__('This will form the rest of the URL for the service holding the user data.. E.g., /v1.0/me'),
        'configuration' => array('size'=>60, 'length'=>100),
      )),*/
      'SCOPES' => new TextboxField(array(
        'label' => $__('Scopes'),
        'required'=>true,
        'hint' => $__('The basic (and required) scope for OpenID Connect is the openid scope. This is space delimited. E.g., openid profile'),
        'configuration' => array('size'=>60, 'length'=>100),
      )),
      'ALLOWED_STAFF_DOMAINS' => new TextboxField(array(
        'label' => $__('Allowed email domains for staff'),
        'hint' => $__('Comma separated values are supported.'),
        'configuration' => array('size'=>60, 'length'=>100),
      )),
      'ALLOWED_CLIENT_DOMAINS' => new TextboxField(array(
        'label' => $__('Allowed email domains for clients'),
        'hint' => $__('Comma separated values are supported.'),
        'configuration' => array('size'=>60, 'length'=>100),
      )),
      'PLUGIN_ENABLED_AWESOME' => new BooleanField(array(
        'label' => $__('Enable support for OSTicket Awesome theme:')
      )),
      'PLUGIN_ENABLED_STAFF' => new BooleanField(array(
        'label' => $__('Enable for staff login:')
      )),
      'PLUGIN_ENABLED_CLIENT' => new BooleanField(array(
        'label' => $__('Enable for client login')
      )),
      'HIDE_LOCAL_STAFF_LOGIN' => new BooleanField(array(
        'label' => $__('Hide local login for staff accounts.')
      )),
      'HIDE_LOCAL_CLIENT_LOGIN' => new BooleanField(array(
        'label' => $__('Hide local login for client accounts.')
      )),
    );
  }
}
