<?php

include_once 'curl_util.php';

define('DEBUGGING', TRUE);

class MicrosoftProviderAuth {

  var $config;
  var $access_token;
  var $login_type;

  function __construct($config, $login_type) {
    $this->config = $config;
    $this->login_type = $login_type;
  }

    function triggerAuth() {
    global $ost;
    $self = $this;

    $redirectUri = rawurlencode(rtrim($ost->getConfig()->getURL(), '/') . '/api/auth/ext');
    $redirectUriNonEncoded = rtrim($ost->getConfig()->getURL(), '/') . '/api/auth/ext';
    $clientId = $this->config->get('CLIENT_ID');
    $clientSecret = $this->config->get('CLIENT_SECRET');
    $scopes = rawurlencode($this->config->get('SCOPES'));
    $resourceUrl = $this->config->get('RESOURCE_ID') . $this->config->get('RESOURCE_ENDPOINT');
    $nonce = $_COOKIE['OSTSESSID'];
    if (!isset($_REQUEST['id_token'])) {
      $authUrl = $this->config->get('AUTHORITY_URL') . $this->config->get('AUTHORIZE_ENDPOINT') . '?client_id='. $clientId . '&response_type=id_token%20code&redirect_uri=' . $redirectUri . '&response_mode=form_post&scope=' . $scopes . '&state=12345&nonce=' . $nonce;
      header('Location: ' . $authUrl);
      exit;
    } else {

        //INFORMATII DUPA AUTENTIFICARE
        //NU CONTIN INFORMATII AMANUNTITE ( CUM SUNT CELE PRIMITE DIN MICROSOFT GRAPH DE MAI JOS)

        //TDOD - Implement real JWT validation

        /*
        $_SESSION[':id_token'] = $_REQUEST['id_token'];
        $_SESSION[':code'] = $_REQUEST['code'];
        $_SESSION[':jwt1'] = json_decode(base64_decode($jwt[0]), true);
        $_SESSION[':jwt2'] = json_decode(base64_decode($jwt[1]), true);
        $_SESSION[':jwt3'] = json_decode(base64_decode($jwt[2]), true);
        */


        $jwt = explode('.', $_REQUEST['id_token']);
        $authInfo = json_decode(base64_decode($jwt[1]), true);

        $_SESSION[':authInfo'] = $authInfo;
        $_SESSION[':openid-ms']['name'] = $authInfo['name'];
        $_SESSION[':openid-ms']['oid'] = $authInfo['oid'];
        if (isset($authInfo['email'])) {
        $_SESSION[':openid-ms']['email'] = $authInfo['email'];
        } elseif (isset($authInfo['preferred_username']) && (filter_var($authInfo['preferred_username'], FILTER_VALIDATE_EMAIL))) {
        $_SESSION[':openid-ms']['email'] = $authInfo['preferred_username'];
        }
        $_SESSION[':openid-ms']['nonce'] = $authInfo['nonce'];

        //Login type
        //Redirectare
        //POSIBILA PROBLEMA DIN CAUZA INVALIDARII RAPIDE A COOKIE-URILOR

        //if ($_COOKIE['LOGIN_TYPE'] === 'CLIENT') header('Location: /login.php');
        //if ($_COOKIE['LOGIN_TYPE'] === 'STAFF') header('Location: /scp/login.php');


      /*
       * Obtinem codul de acces al utilizatorului
       */

        // Primire access token --- INFO: https://docs.microsoft.com/en-us/graph/auth-v2-user

        //$_SESSION[':redirectUri'] = $redirectUri;
        //$_SESSION[':redirectUri2'] = rtrim($ost->getConfig()->getURL(), '/') . '/api/auth/ext';
        $post_fields = array(
                'grant_type' => 'authorization_code',
                'code' => $_REQUEST['code'], // codul primit din pasul de autorizare de mai devreme
                'client_secret' => $clientSecret,
                'client_id' => $clientId,
                'scope' => $this->config->get('SCOPES'),
                'redirect_uri' => $redirectUriNonEncoded
        );

        // Url access token
        $url = $this->config->get('AUTHORITY_URL')
          . $this->config->get('ACCESS_ENDPOINT');

        // Curl post pentru obtinerea unui access_token
        $result = curl_post($url, $post_fields);
        //$_SESSION[':AccessURL'] = $url;
        //$_SESSION[':AccessResponse'] = $result;

        $json_info = json_decode($result, true);
        $access_token = $json_info['access_token'];
        $access_type = $json_info['token_type']; // Azure suporta doar Bearer type
        $_SESSION[':access_token'] = $access_token;
        //$_SESSION[':access_type'] = $access_type;

        /*
         * Obtinem profilul utilizatorului
         */

        // Setam codul de autorizare in header
        $headers = array(
            'Authorization: '. $access_type. ' ' .$access_token
        );

        //$_SESSION[':graphHeaders'] = $headers;

        // Curl get pentru obtinerea profilului
        $result = curl_get($this->config->get('RESOURCES_URL'), $headers);

        // Salvare informatii user
        $_SESSION[':profile'] = $result;

        if($this->login_type == 'CLIENT') {
            Http::redirect(ROOT_PATH . 'profile.php');
        }
        else if($this->login_type == 'STAFF'){
            Http::redirect(ROOT_PATH . 'scp/login.php');
        }

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
  if ($_SERVER['SCRIPT_NAME'] === '/login.php' || $_SERVER['SCRIPT_NAME'] === '/open.php') {
    setcookie('LOGIN_TYPE','CLIENT', time() + 180, "/");
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
  $this->MicrosoftAuth = new MicrosoftProviderAuth($config, 'CLIENT');
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
    $MicrosoftAuth = $this->MicrosoftAuth->triggerAuth();
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
    if ($_SERVER['SCRIPT_NAME'] === '/scp/login.php') {
      setcookie('LOGIN_TYPE','STAFF', time() + 180, "/");
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
    $this->MicrosoftAuth = new MicrosoftProviderAuth($config, 'STAFF');
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
    $MicrosoftAuth = $this->MicrosoftAuth->triggerAuth();
  }
}
