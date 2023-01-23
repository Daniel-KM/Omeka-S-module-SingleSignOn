Single Sign-On (module for Omeka S)
===================================

> __New versions of this module and support for Omeka S version 3.0 and above
> are available on [GitLab], which seems to respect users and privacy better
> than the previous repository.__

[Single Sign-On] is a module for [Omeka S] that allows users to authenticate
automatically through single sign-on (SSO) via ([SAML]) and the identity provider
(IdP) of your institution or any external service.

Local users can still connect via the local passwords if they have one.


Installation
------------

The module uses an external library, [onelogin/php-saml], so use the release zip to
install it, or use and init the source.

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

The service must be configured on the Omeka part and the identity provider (IdP)
part.

- For Omeka, go to the config form and fill the params of the IdP.
- For the IdP, register Omeka as a service provider (SP) with the metadata
  provided at https://example.org/sso/metadata.

Then, users will be able to log in at https://example.org/sso/login.


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
[onelogin/php-saml]: https://github.com/SAML-Toolkits/php-saml
[Installing a module]: https://omeka.org/s/docs/user-manual/modules/#installing-modules
[SingleSignOn.zip]: https://gitlab.com/Daniel-KM/Omeka-S-module-SingleSignOn/-/releases
[module issues]: https://gitlab.com/Daniel-KM/Omeka-S-module-SingleSignOn/-/issues
[CeCILL v2.1]: https://www.cecill.info/licences/Licence_CeCILL_V2.1-en.html
[GNU/GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[FSF]: https://www.fsf.org
[OSI]: https://opensource.org
[MIT]: https://github.com/SAML-Toolkits/php-saml/blob/master/LICENSE
[GitLab]: https://gitlab.com/Daniel-KM
[Daniel-KM]: https://gitlab.com/Daniel-KM "Daniel Berthereau"
