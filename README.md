Single Sign-On (module for Omeka S)
===================================

> __New versions of this module and support for Omeka S version 3.0 and above
> are available on [GitLab], which seems to respect users and privacy better
> than the previous repository.__

[Single Sign-On] is a module for [Omeka S] that allows users to authenticate
automatically through single sign-on (SSO) via [SAML] and the identity provider
(IdP) of your institution or any external service.

Local users can still connect via the local passwords if they have one.

Note that [Shibboleth] is a derivative of Saml, so the [module Shibboleth] will
be deprecated soon, once some missing features will be implemented in this
module.


Installation
------------

The module uses an external library, [onelogin/php-saml], so use the release zip to
install it, or use and init the source.

You may install the module [Guest] or [Guest Role] to give a non-admin role to
new users. This is important for security, else the default role will be
"researcher", who can access admin board. Of course, once authenticated, an
admin can set the right role.

See general end user documentation for [installing a module].

* From the zip

Download the last release [SingleSignOn.zip] from the list of releases (the
master does not contain the dependency), and uncompress it in the `modules`
directory.

* From the source and for development

If the module was installed from the source, rename the name of the folder of
the module to `SingleSignOn`, go to the root of the module, and run:

```sh
composer install --no-dev
```


Quick start
-----------

For security, the service must be configured on the Omeka part and the identity
provider (IdP): Omeka needs to know the IdP and, the IdP requires to allow
Omeka as a SAML service provider (SP).

- For Omeka, go to the config form and fill the params of your IdP.
- For the IdP, register Omeka as a service provider with the metadata provided
  at https://example.org/sso/metadata.

Then, users will be able to log in at https://example.org/sso/login.

Params available to config SP and IdP in Omeka, and that should be updated when
the IdP is updated. To get the metadata from the saml idp server, just go to its
url, for example https://idp.example.org/idp/shibboleth.

- services:
  - log in (sso): required.
  - log out (sls): Log out is not recommended, because it can have bad side
    effects when deconnecting from other services.
  - jit: register new users just in time, so create account inside Omeka
    automatically, else the users should be created by an administrator first
    inside Omeka.
  - Update user name: Update the name in Omeka when it is updated in IdP.

- Service provider:
  - Metadata content type
  - Metadata content disposition: these two options allow to fix some badly
    configured IdP. To display the metadata directly in a browser, use "application/xml"
    and "inline".
  - Metadata mode: some IdP don't manage xml fully, so a basic mode is provided
    that removes the prefixes of the xml metadata.
  - Name ID format of the service provider: If the default config (persistent)
    does not work, try to change  the format of the name to set in element `<md:NameIDFormat>`,
    for example "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".
  - SP certificate path: Some IdP require certificates. If needed, set the path
    to it. It should contains a directory "certs/" with at least `sp.crt` and
    `sp.key`. It must be outside of the web server or protected, for example
    with a .htaccess.
  - SP public certificate
  - SP private key: if the IdP requires a certificate and you cannot use the
    path above, you can fill the public certificate and the private key. The
    format should be x509. You can use the ssl keys of your website.
    **Warning**: All keys have an expiration date, so add them into your
    planning (anyway your users will warn you).

- Identity Provider:
  - Identity provider id: this is the url set in attribute `entityID` of xml
    element `<md:EntityDescriptor>`, for example `https://idp.example.org`.
    Important: for some IDP, the scheme must not be set, so try `idp.example.org`
    too. Just fill the content of the attribute.
  - IdP single sign-on (SSO) endpoint: Full url set in attribute `Location` of xml
    element `<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`,
    for example "https://idp.example.org/idp/profile/SAML2/Redirect/SSO".
  - IdP single log out (SLO)  endpoint: Full url set in attribute `Location` of xml
    element `<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`,
    for example "https://idp.example.org/idp/profile/SAML2/Redirect/SLO".
  - Public X.509 certificate of the IdP: it is required.
  - Map between IdP and Omeka keys: used to indicate the keys to use to create
    and authenticate the good user with a specific role.

For the map, in most of the cases, use:
```
mail = email
displayName = name
```

The role can be added: `role = role`. If not set, new users will be "researcher" or "guest".
Anyway, for the role, if a map is done, it is recommended to use "guest" or
"researcher", then to update it manually in admin board. "guest" is used only
when module [Guest] or [Guest Role] is active, or another module that creates
this role. For security, don't set an admin role. Of course, an admin can update
the role after the first authentication.

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


TODO
----

- [ ] Autoconfig SP via xml file.
- [ ] Multiple IdP.
- [ ] Mapping roles (see module Shibboleth).
- [ ] Extra settings, in particular locale (see module Shibboleth).
- [ ] Add logo and site name (see onelogin config and https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ui/v1.0/os/sstc-saml-metadata-ui-v1.0-os.html).
- [ ] Force sso login (with dynamic check of config first).


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

* Copyright Daniel Berthereau, 2023 (see [Daniel-KM] on GitLab)


[Single Sign-On]: https://gitlab.com/Daniel-KM/Omeka-S-module-SingleSignOn
[Omeka S]: https://omeka.org/s
[SAML]: https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language
[Shibboleth]: https://www.shibboleth.net
[module Shibboleth]: https://gitlab.com/Daniel-KM/Omeka-S-module-Shibboleth
[onelogin/php-saml]: https://github.com/SAML-Toolkits/php-saml
[Installing a module]: https://omeka.org/s/docs/user-manual/modules/#installing-modules
[SingleSignOn.zip]: https://gitlab.com/Daniel-KM/Omeka-S-module-SingleSignOn/-/releases
[Guest]: https://gitlab.com/Daniel-KM/Omeka-S-module-Guest
[Guest Role]: https://github.com/biblibre/omeka-s-module-GuestRole
[module issues]: https://gitlab.com/Daniel-KM/Omeka-S-module-SingleSignOn/-/issues
[SamlTest.id]: https://samltest.id
[CeCILL v2.1]: https://www.cecill.info/licences/Licence_CeCILL_V2.1-en.html
[GNU/GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[FSF]: https://www.fsf.org
[OSI]: https://opensource.org
[MIT]: https://github.com/SAML-Toolkits/php-saml/blob/master/LICENSE
[GitLab]: https://gitlab.com/Daniel-KM
[Daniel-KM]: https://gitlab.com/Daniel-KM "Daniel Berthereau"
