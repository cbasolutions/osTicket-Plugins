# OpenID Authentication for Microsoft in osTicket

### Current Version Notes:
#### Initial Release - 2018-03-29
#### Version .1

* Implementation of Open ID authentication for osTicket. 
* Tested with personal and work accounts
* Tested on LAMP stack with PHP 7.0.28, osTicket v1.10.1
* Tested on LEMP stack with PHP 7.2.3-1, osTicket v1.10.1
  * osTicket on LEMP requires additional rewrite rules. This [recipe](https://www.nginx.com/resources/wiki/start/topics/recipes/osticket/) is a good starting point. You'll want to change the following:
    ```Nginx
    location ~ ^/api/(?:tickets|tasks).*$ {
      try_files $uri $uri/ /api/http.php?$query_string;
    }
    ```
    to:
    ```Nginx
    location ~ ^/api/(?:tickets|tasks|auth).*$ {
      try_files $uri $uri/ /api/http.php?$query_string;
    }
    ```
  * osTicket has other issues with PHP 7.2
  

##### Features
* Configuration options for auth URL, endpoint, scope, client ID (application ID), and secret
* Additional options for domain whitelists on staff and client logins, enabling the plugin separately on staff and client logins, plus hiding the local login sections

   Hiding the local logins allows for public registration to be enabled so that accounts don't have to be created in advance
![screenshot][screenshot]

##### Installation instructions
* Upload the [phar file](https://raw.githubusercontent.com/cbasolutions/osTicket-Plugins/master/auth-openid-MS/auth-openid-MS.phar) to your osTicket/include/plugins directory.

##### TODO
* Implement validation of id_token. Currently we just parse the token for the user data.
* Implement ability to use custom sign-in button. Micrsosoft has described branding requirements [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-branding-guidelines). 
* Error handling. If something doesn't map, it'll just go back to the login screen. 




[screenshot]: https://raw.githubusercontent.com/cbasolutions/osTicket-Plugins/master/auth-openid-MS/img/screenshot.png
