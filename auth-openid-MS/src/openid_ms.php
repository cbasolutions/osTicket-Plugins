<?php

// Enumeration-type abstract class just for defining to set of possible login types
abstract class LoginType
{
    // - End user:
    const CLIENT = 0;
    // - Agent/Admin user:
    const STAFF = 1;
}

class MicrosoftProviderAuth {

  var $config;
  var $access_token;

  function __construct($config) {
    $this->config = $config;
  }

  function triggerAuth($login_type = LoginType::CLIENT) {
    global $ost;
    $self = $this;

    $home_url = rtrim($ost->getConfig()->getURL(), '/');
    $home_url_sections = parse_url($home_url);
    $home_url_path = isset($home_url_sections["path"]) ? $home_url_sections["path"] : "";

    if (!isset($_REQUEST['id_token'])) {
      $redirect_url = $home_url . '/api/auth/ext';
      $clientId = $this->config->get('CLIENT_ID');
      $scopes = $this->config->get('SCOPES');
      // N.B.: Completely regenerate the current session id to ensure the session is now all clean and valid
      $ost->session->regenerate_id();
      $nonce = session_id();
      $authUrl = $this->config->get('AUTHORITY_URL') . $this->config->get('AUTHORIZE_ENDPOINT') . '?client_id='. rawurlencode($clientId) .
        '&response_type=id_token%20code&redirect_uri=' . rawurlencode($redirect_url) . '&response_mode=form_post&scope=' . rawurlencode($scopes) .
        '&state=12345&nonce=' . rawurlencode($nonce);
      header('Location: ' . $authUrl);
      //error_log(__FILE__ . ":" . __LINE__ . " - " . __CLASS__ . "::" . __METHOD__ . " - exit #01 - headers_list(): \"" . print_r(headers_list(), TRUE) . "\"");
      exit;
    } else {
      //TODO - Implement real JWT validation
      $jwt = explode('.', $_REQUEST['id_token']);
      $authInfo = json_decode(base64_decode($jwt[1]), true);
      $_SESSION[':openid-ms']['name'] = $authInfo['name'];
      $_SESSION[':openid-ms']['oid'] = $authInfo['oid'];
      if (isset($authInfo['email'])) {
        $_SESSION[':openid-ms']['email'] = $authInfo['email'];
      } elseif (isset($authInfo['preferred_username']) && (filter_var($authInfo['preferred_username'], FILTER_VALIDATE_EMAIL))) {
        $_SESSION[':openid-ms']['email'] = $authInfo['preferred_username'];
      }
      $_SESSION[':openid-ms']['nonce'] = $authInfo['nonce'];
      header('Location: ' . $home_url_path . ( $login_type === LoginType::STAFF ? '/scp' : '' ) . '/login.php');
      //error_log(__FILE__ . ":" . __LINE__ . " - " . __CLASS__ . "::" . __METHOD__ . " - exit #02 - headers_list(): \"" . print_r(headers_list(), TRUE) . "\"");
      exit;
    }
  }
}


class MicrosoftOpenIDClientAuthBackend extends ExternalUserAuthenticationBackend {
  static $id = "openid_ms.client";
  static $name = "Micrsoft OpenID Auth - Client";

  static $sign_in_image_url = "https://docs.microsoft.com/en-us/azure/active-directory/develop/media/active-directory-branding-guidelines/sign-in-with-microsoft-light.png";
  static $service_name = "Microsoft OpenID Auth - Client";

function __construct($config) {
  $this->config = $config;
  # N.B.: check that "$_SERVER['SCRIPT_NAME']" ends with '/login.php' or '/open.php' or '/index.php', but without '/scp' just before (e.g. not ending with '/scp/login.php'):
  if (preg_match("#(?<!\/scp)\/(login|open|index)\.php$#", $_SERVER['SCRIPT_NAME'])) {
    if ($this->config->get('HIDE_LOCAL_CLIENT_LOGIN')) {
      if ($this->config->get('PLUGIN_ENABLED_AWESOME')) {
        ?>
        <script>
          window.onload = function () {
          "use strict";
          document.getElementById("one-view-page").remove();
          document.getElementById("middle-view-page").remove();
          /*something odd happens to this DIV when using these hacks.*/
          document.getElementById("header-logo-subtitle").remove();
          var eAuth = document.getElementsByClassName("external-auth");
          while (eAuth[0].nextSibling) {
            eAuth[0].nextSibling.remove();
          }
        };
      </script>
      <?php
      } else {
        ?>
        <script>window.onload = function() {
          var loginBox = document.getElementsByClassName('login-box');
          loginBox[0].remove();
          var eAuth = document.getElementsByClassName('external-auth');
          while (eAuth[0].nextSibling) {
            eAuth[0].nextSibling.remove();
          }
        };
        </script>
      <?php
      }
    }
  }
  $this->MicrosoftAuth = new MicrosoftProviderAuth($config);
}

    function supportsInteractiveAuthentication() {
        return false;
    }

    function signOn() {
      global $errors;
      $self = $this;

      if (isset($_SESSION[':openid-ms']['email'])) {
        // Check email for access
        $emailDomain = substr(strrchr($_SESSION[':openid-ms']['email'], "@"), 1);
        $allowedDomains = explode(',', $this->config->get('ALLOWED_CLIENT_DOMAINS'));
        if (in_array(strtolower($emailDomain), array_map('strtolower', $allowedDomains)) || ($this->config->get('ALLOWED_CLIENT_DOMAINS') == '')) {
          if (($acct = ClientAccount::lookupByUsername($_SESSION[':openid-ms']['email'])) && $acct->getId() && ($client = new ClientSession(new EndUser($acct->getUser())))) {
          return $client;
        } else {
          $info = array(
            'email' => $_SESSION[':openid-ms']['email'],
            'name' => $_SESSION[':openid-ms']['name'],
          );
          return new ClientCreateRequest($this, $info['email'], $info);
        }
      }
    }
  }

  static function signOut($user) {
    parent::signOut($user);
    unset($_SESSION[':openid-ms']);
    //https://login.microsoftonline.com/common/oauth2/logout?post_logout_redirect_uri=http%3A%2F%2Flocalhost%2Fmyapp%2F
  }

  function triggerAuth() {
    parent::triggerAuth();
    $MicrosoftAuth = $this->MicrosoftAuth->triggerAuth(LoginType::CLIENT);
  }
}


class MicrosoftOpenIDStaffAuthBackend extends ExternalStaffAuthenticationBackend {
  static $id = "openid_ms.staff";
  static $name = "Micrsoft OpenID Auth - Staff";
  static $service_name = "Microsoft OpenID Auth - Staff";
  static $sign_in_image_url = "https://docs.microsoft.com/en-us/azure/active-directory/develop/media/active-directory-branding-guidelines/sign-in-with-microsoft-light.png";

  function __construct($config) {
    $this->config = $config;
    $sign_in_image_url = $this->config->get('LOGIN_LOGO');
    # N.B.: check that "$_SERVER['SCRIPT_NAME']" ends with '/scp/login.php' or '/scp/index.php':
    if (preg_match("#/scp/(login|index)\.php$#", $_SERVER['SCRIPT_NAME'])) {
      if ($this->config->get('HIDE_LOCAL_STAFF_LOGIN')) {
        ?>
        <script>window.onload = function() {
          var login = document.getElementById('login');
          login.remove();
        };
        </script>
      <?php
      }
    }
    $this->MicrosoftAuth = new MicrosoftProviderAuth($config);
  }

  function supportsInteractiveAuthentication() {
    return false;
  }

  function signOn() {
    if (isset($_SESSION[':openid-ms']['email'])) {
      $emailDomain = substr(strrchr($_SESSION[':openid-ms']['email'], "@"), 1);
      $allowedDomains = explode(',', $this->config->get('ALLOWED_STAFF_DOMAINS'));
      if (in_array(strtolower($emailDomain), array_map('strtolower', $allowedDomains)) || ($this->config->get('ALLOWED_STAFF_DOMAINS') == '')) {
        if (($staff = StaffSession::lookup(array('email' => $_SESSION[':openid-ms']['email'])))
        && $staff->getId()
        ) {
          if (!$staff instanceof StaffSession) {
            // osTicket <= v1.9.7 or so
            $staff = new StaffSession($user->getId());
          }
          return $staff;
        }
        else
        $_SESSION['_staff']['auth']['msg'] = 'Have your administrator create a local account';
      }
    }
  }
  
  static function signOut($user) {
    parent::signOut($user);
    unset($_SESSION[':openid-ms']);
    //https://login.microsoftonline.com/common/oauth2/logout?post_logout_redirect_uri=http%3A%2F%2Flocalhost%2Fmyapp%2F
  }

  function triggerAuth() {
    parent::triggerAuth();
    $MicrosoftAuth = $this->MicrosoftAuth->triggerAuth(LoginType::STAFF);
  }
}
