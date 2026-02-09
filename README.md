Single Sign-On (module for Omeka S)
===================================

> __New versions of this module and support for Omeka S version 3.0 and above
> are available on [GitLab], which seems to respect users and privacy better
> than the previous repository.__

[Single Sign-On] is a module for [Omeka S] that allows users to authenticate
automatically through single sign-on (SSO) via [SAML] and the identity provider
(IdP) of your institution or any external service. To authenticate through
multiple IdPs individually defined or defined via a federation of identity
providers like [Renater] is possible too. The certificates of the IdP can be
automatically updated each day too.

Local users can still connect via the local passwords if they have one, but an
option allow to disallow local login.

Note that [Shibboleth] is an extension of Saml, so the [module Shibboleth] is
deprecated, since all its features are implemented in this module, without
installing a specific package on the server.


Installation
------------

See general end user documentation for [installing a module].

This module is dependant of module [Common], that should be installed first.

You may install the module [Guest] or [Guest Role] to give a non-admin role to
new users.
The module uses an external library, [onelogin/php-saml], so use the release zip
to install it, or use and init the source.

- Via composer (recommended)

```sh
composer install --no-dev
```

- From the zip

Download the last release [SingleSignOn.zip] from the list of releases, and
uncompress it in the `modules` directory. Check for the name of the directory,
that should be `SingleSignOn`.

- For test

The module includes a comprehensive test suite with unit and functional tests.
Run them from the root of Omeka:

```sh
vendor/bin/phpunit -c modules/Urify/phpunit.xml --testdox
```


Quick start
-----------

### Configuration

For security, each service must be configured on the Omeka part and the identity
provider (IdP) part: Omeka needs to know each IdP and, each IdP requires to
allow Omeka as a SAML service provider (SP).

- For Omeka, go to the config form and fill the params of your IdP.
- For the IdP, register Omeka as a service provider with the metadata provided
  at https://example.org/sso/metadata.

Then, users will be able to log in at https://example.org/sso/login.

Params available to config SP and IdP in Omeka, and that should be updated when
the IdP is updated. To get the metadata from the saml idp server, just go to its
url, for example https://idp.example.org/idp/shibboleth. And most of the times,
you just need to feel this url, other idp fields will be automatically filled.

#### Main options

- Services:
  - log in (sso): required.
  - log out (sls): Log out is not recommended, because it can have bad side
    effects when deconnecting from other services.
  - register (jit): register new users just in time, so create account inside
    Omeka automatically, else the users should be created by an administrator
    first inside Omeka.
  - Update user name: Update the name in Omeka when it is updated in IdP.

- Default role:

  The default role is "researcher", who can access admin board, or "guest" if
  the module is installed. Of course, once authenticated, an admin can set the
  right role. For security, the admin roles are forbidden for new users.

- Redirect page after log in

#### Service provider (SP)

The site (Omeka) is the service provider.

- Specific entity id, in particular when behind a proxy. Defaut is the url of
  the host.
- Specific host, in particular when behind a proxy.
- Metadata content type
- Metadata content disposition: these two options allow to fix some badly
  configured IdP. To display the metadata directly in a browser, use "application/xml"
  and "inline".
- Metadata mode: some IdP don't manage xml fully, so a basic mode is provided
  that removes the prefixes of the xml metadata.
- Name ID format of the service provider: If the default config (unspecified)
  does not work, try to change  the format of the name to set in element `<md:NameIDFormat>`,
  for example "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".
- Security: by default, the security measures are all enabled. In the case where
  an IdP does not respect one of the requirements, it is possible to disable it.
  - [Renater]:
    - Disable the requirement on signing assertions.
  - [saml2int] (Interoperable SAML 2.0 Web Browser SSO Profile):
    - Disable SP signing of auth request;
    - Enable Require assertions signed by IdP;
    - Enable Require assertions to be encrypted by IdP if the server is not https;
    - Disable Require Name Id to be encrypted by IdP.
  - [Kantara Initiative] (SAML V2.0 Deployment Profile for Federation Interoperability)
    Kantara is a continuation and a rebrand of saml2int, so the previous options
    may be used.
  - Microsoft ADFS (Active Directory Federation Services):
    - Enable the option for compatibility layer.
    - Manage other options according to specific configurations and versions.
- SP certificates:
  Some IdPs require certificates to sign and to encrypt responses. There are
  three ways to define them for signature and encryption: a path to the
  certificate and private key, a  copy-paste in fields or a creation.
  - SP certificate path: The path should contains a directory "certs/" with at
    least the files `sp.crt` and `sp.key`. It must be outside of the web server
    or protected, for example with a .htaccess.
  - SP public certificate and SP private key: you can fill the public
    certificate and the private key. The format should be x509.
    **Warning**: All keys have an expiration date, so add them into your
    planning (anyway your users will warn you), even if such keys are usually
    long term (more than 10 years).
  - Creation of an self-signed certificate. Check the box and fill the optional
    keys: countryName, stateOrProvinceName, localityName, organizationName,
    organizationalUnitName, commonName, and emailAddress.
  - [Shibboleth] may require a signing certificate and an encryption certificate,
    so set the two fields and copy them in the config of Shibboleth. The option
    to require signing assertion may be disabled with [Renater].

#### Identity provider (IdP)

The identity provider can be a federation of identity providers, in which case
the config is automatic. If you have a federation not implemented in the module,
you can set it in the Omeka config/local.config.php under key `[singlesignon][federations]`.

When a federation is set, the locally defined idps override the params of the
same idps managed by the federation. Each idp can have a specific config.

- Update mode: define if the config will be updated automatically. It is useful,
  in particular for the certificate, that may have a limited lifetime.
  In some cases, two options are needed.
  - skip update of the entity id: allow to fix possible issue with reverse
    proxies.
  - use the certificates provided by the federation, not the idp ones: may fixes
    issues when the certificates included in the federation are not the same
    than the local idp.
- Identity provider metadata url: When set, the form will be automatically
  filled and updated each day, in particular for the certificate. It is
  recommended to fill it. When enable, there is a shortcut to get these public
  metadata of the IdP: https://example.org/sso/metadata/idp.external.example.org.
- Identity provider id: this is the url set in attribute `entityID` of xml
  element `<md:EntityDescriptor>`, for example `https://idp.example.org`.
  Important: for some IdP, the scheme must not be set, so try `idp.example.org`
  too. Just fill the content of the attribute.
- Identity provider name: the display name of the IdP, used for the links.
- IdP single sign-on (SSO) endpoint: Full url set in attribute `Location` of xml
  element `<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`,
  for example "https://idp.example.org/idp/profile/SAML2/Redirect/SSO".
- IdP single log out (SLO)  endpoint: Full url set in attribute `Location` of xml
  element `<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`,
  for example "https://idp.example.org/idp/profile/SAML2/Redirect/SLO".
- Public X.509 certificate of the IdP (signature): it is required.
- Public X.509 certificate of the IdP (encryption): it is optional.
- Maps between IdP and Omeka

#### Managing IdP attributes and Omeka settings

Most of the times, the default config is fine, included Shibboleth. If needed,
three fields allow to manage links between an idp and Omeka and specific
settings.

- Map between IdP and Omeka keys: It is used to indicate the keys to use to
  create and authenticate the good user data (name, email, role). Other keys,
  for example "locale" or "userprofile_param", will be stored in user settings.

  Simple example:

  ```
  mail = email
  displayName = name
  ```

  Example with more fields (idp attribute = omeka setting name):

  ```
  mail = email
  displayName = name
  role = role
  memberOf = role
  language = locale
  anAttribute = singlesignon_xxx
  anotherAttribute = userprofile_yyy
  yetAnotherAttribute = user_setting_zzz
  ```

  A living config for a federation and specific rights for some idps, used by
  modules [Access] and [Contribute]:

  ```
  eduPersonAffiliation = singlesignon_person_affiliation
  supannEntiteAffectation = singlesignon_entite_affectation
  eduPersonPrincipalName = singlesignon_eppn
  givenName = singlesignon_given_name
  surName = singlesignon_sur_name
  ```

- Map between IdP and Omeka roles: List of IdP and Omeka roles separated by "=".
  It is not recommended to set admin roles in mapping, but to update the role
  manually in admin part once created. "guest" is used only when module
  [Guest] or [Guest Role] is active, or another module that creates this role.
  For security, don't set an admin role. Of course, an admin can update the
  role after the first authentication. If not set, new users will be "researcher"
  or "guest", if the role exists.

  Example for the roles (idp role = omeka role):

  ```
  director = global_admin
  supervisor = site_admin
  librarian = editor
  ```

- User settings: This field is not a mapping between the IdP and Omeka, but a
  simple list of keys/values pairs that will be stored in user settings when a
  user is created.

  Values are not updated next times the user logs in.

  The format is "omeka setting name = value":

  ```
  locale = fr
  guest_agreed_terms = 1
  userprofile_xxx = value x
  user_setting_yyy = value y
  ```

Warning: The keys in the first fields are updated only when the options to
update user name and to update user settings are enabled. The last field is
never updated.

### Fix config

The config of the security options may be complex. You may use the [Firefox]
extension [SAML Message Decoder] extension to check the messages shared between
the SP and the IdP.

### Testing on SamlTest.id

For testing, you can use a free service like [SamlTest.id], that avoids to
config the IdP. Fill these params https://samltest.id/download (IdP part) in
config form; then register your server in https://samltest.id/upload.php,
setting the url https://example.org/sso/metadata or, if not loaded, send the
output of the url as an xml file and upload it, then try to login with one of
the specified users.

**WARNING** SamlTest.id keeps the last config of each service provider. So once
tests are finished, you should disable all features of the module, then upload
the new config to SamlTest.id, then reenable your features. Anyway, the validity
of the service provider metadata is 48 hours, so the IdP will be disabled after
that. And if the IdP is no more registered in Omeka, it won't be able to log in.

### Fix when metadata cannot be retrieved for an IdP

When saving the configuration, if the metadata for an IdP cannot be fetched
(SSL certificate issue on the IdP side, network timeout, etc.), the existing
configuration is preserved and a warning is displayed. The save proceeds
normally for all IdPs. Users can still authenticate with the existing config.

If the IdP has no existing config (new IdP with no entity id or SSO url), it
will be marked as invalid and should be fixed or removed.

To check a specific IdP SSL certificate chain, you can use:

```sh
curl -vI https://idp.example.org 2>&1
```

### Local login

To disallow local login, append this to the file config/local.config.php of Omeka:

```php
    'authentication' => [
        // Warning: check your idp access first, because when set true,
        // all current locally logged users will be logged out.
        'forbid_local_login' => true,
        // Unless this option is false: in that case, current sessions are kept.
        'logout_logged_users' => false,
    ],
```


TODO
----

- [x] Autoconfig SP via xml file.
- [x] Autoconfig IdP via xml file or url.
- [x] Multiple IdP.
- [x] Mapping roles (see module Shibboleth).
- [x] Extra settings, in particular locale (see module Shibboleth).
- [ ] Add logo and site name (see onelogin config and https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ui/v1.0/os/sstc-saml-metadata-ui-v1.0-os.html).
- [x] Store user idp in user settings instead of a new table!
- [x] Force sso login (with dynamic check of config first).
- [ ] Use a Laminas SSO adapter instead of a specific url.
- [ ] Future certs and metadata cert to sign (see directory certs in vendor one-login).
- [ ] Integrate the discovery protocol for login (two steps login, to avoid selecting the idp of the federation).
- [ ] Integrate the protocol MDQ for federation (see https://mdq.federation.renater.fr/)
- [ ] Manage change of email by the user when the unique id is not the email, or the university change its domain.
- [ ] Manage given and family names separately.
- [ ] Add options to get attributes and maps for the federated idps.
- [-] Allow to log in without registering SP in the IdP (Unsolicited Login Initiator), but may be a security issue.
- [-] Use gz version of xml files from renater after checking if it is quicker. Useless: the http client automatically uses gz.


Warning
-------

Use it at your own risk.

It’s always recommended to backup your files and your databases and to check
your archives regularly so you can roll back if needed.


Troubleshooting
---------------

See online issues on the [module issues] page on GitLab.


License
-------

### Module

This module is published under the [CeCILL v2.1] license, compatible with
[GNU/GPL] and approved by [FSF] and [OSI].

This software is governed by the CeCILL license under French law and abiding by
the rules of distribution of free software. You can use, modify and/ or
redistribute the software under the terms of the CeCILL license as circulated by
CEA, CNRS and INRIA at the following URL "http://www.cecill.info".

As a counterpart to the access to the source code and rights to copy, modify and
redistribute granted by the license, users are provided only with a limited
warranty and the software’s author, the holder of the economic rights, and the
successive licensors have only limited liability.

In this respect, the user’s attention is drawn to the risks associated with
loading, using, modifying and/or developing or reproducing the software by the
user in light of its specific status of free software, that may mean that it is
complicated to manipulate, and that also therefore means that it is reserved for
developers and experienced professionals having in-depth computer knowledge.
Users are therefore encouraged to load and test the software’s suitability as
regards their requirements in conditions enabling the security of their systems
and/or data to be ensured and, more generally, to use and operate it in the same
conditions as regards security.

The fact that you are presently reading this means that you have had knowledge
of the CeCILL license and that you accept its terms.

### Libraries

- onelogin/php-saml is published under the license [MIT].


Copyright
---------

* Copyright Daniel Berthereau, 2023-2026 (see [Daniel-KM] on GitLab)

This module was built for a new section of [Numistral] the digital library of
the [Bibliothèque nationale et universitaire de Strasbourg] (BNU), the [Université de Haute-Alsace] (UHA).
and the [Université de Strasbourg] (UNISTRA). New features were implemented for
[Insa Lyon] and [Université Claude Bernard Lyon 1].


[Single Sign-On]: https://gitlab.com/Daniel-KM/Omeka-S-module-SingleSignOn
[Omeka S]: https://omeka.org/s
[SAML]: https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language
[Shibboleth]: https://www.shibboleth.net
[module Shibboleth]: https://gitlab.com/Daniel-KM/Omeka-S-module-Shibboleth
[onelogin/php-saml]: https://packagist.org/packages/onelogin/php-saml
[Common]: https://gitlab.com/Daniel-KM/Omeka-S-module-Common
[installing a module]: https://omeka.org/s/docs/user-manual/modules/#installing-modules
[SingleSignOn.zip]: https://gitlab.com/Daniel-KM/Omeka-S-module-SingleSignOn/-/releases
[Guest]: https://gitlab.com/Daniel-KM/Omeka-S-module-Guest
[Guest Role]: https://github.com/biblibre/omeka-s-module-GuestRole
[Access]: https://gitlab.com/Daniel-KM/Omeka-S-module-Access
[Contribute]: https://gitlab.com/Daniel-KM/Omeka-S-module-Contribute
[Renater]: https://www.renater.fr
[saml2int]: http://saml2int.org/profile/current
[Kantara Initiative]: https://kantarainitiative.github.io/SAMLprofiles/saml2int.html
[Shibboleth]: https://www.shibboleth.net
[Firefox]: https://www.firefox.com
[SAML Message Decoder]: https://addons.mozilla.org/fr/firefox/addon/saml-message-decoder-extension
[SamlTest.id]: https://samltest.id
[module issues]: https://gitlab.com/Daniel-KM/Omeka-S-module-SingleSignOn/-/issues
[CeCILL v2.1]: https://www.cecill.info/licences/Licence_CeCILL_V2.1-en.html
[GNU/GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[FSF]: https://www.fsf.org
[OSI]: https://opensource.org
[MIT]: https://github.com/SAML-Toolkits/php-saml/blob/master/LICENSE
[Numistral]: https://omeka.numistral.fr
[Bibliothèque nationale et universitaire de Strasbourg]: https://www.bnu.fr
[Université de Haute-Alsace]: https://www.uha.fr
[Université de Strasbourg]: https://www.unistra.fr
[Insa Lyon]: https://www.insa-lyon.fr
[Université Claude Bernard Lyon 1]: https://www.univ-lyon1.fr
[GitLab]: https://gitlab.com/Daniel-KM
[Daniel-KM]: https://gitlab.com/Daniel-KM "Daniel Berthereau"
