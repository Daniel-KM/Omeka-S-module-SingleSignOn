��    �      �  �   L	      `  u   a  ?   �  <     p   T     �  
   �  �   �  @   �  Q   �     <      [  $   |  	   �  ]   �  "   	  E   ,  %   r     �  R   �  0   �  5   $  B   Z  !   �  5   �     �  
     C     Z   Q  �   �  �   |  �   L  A        J     Q  A   _     �     �  >   �               9  Q   G  <   �  ,   �  Z     S   ^  F   �  :   �  +   4  ;   `  z   �       �        �       !     K   6     �     �     �     �     �     �  �   �  (   �  4   �  8   �  �     <   �  #   �            +   $     P     p     �     �  6   �  5   �     "  3   >     r     z     �  �   �  R   {  &   �  4   �     *   -   J      x      �   I   �   9   �   ?   3!  �   s!  �   �!  }   �"  "   x#     �#     �#  *   �#  *   �#  7   "$  3   Z$  !   �$  /   �$  5   �$      %  :   7%  '   r%  :   �%  u   �%  a   K&  6   �&  .   �&  6   '  <   J'  2   �'  G   �'  a   (  E   d(  <   �(  �   �(  �   {)  �   *  �   �*  .   |+  �   �+  .   Q,  A   �,  5   �,  	   �,     -     -  0   -  4   P-  4   �-  3   �-     �-  b   
.  >   m.  c   �.  U   /     f/     �/    �/  �   �0  b   61  O   �1  �   �1     x2     �2  7  �2  I   �3  t   4  ,   �4  0   �4  -   �4     5  {   &5  -   �5  s   �5  *   D6     o6  R   w6  >   �6  @   	7  K   J7  0   �7  Z   �7     "8     48  P   A8  {   �8  �   9  �   �9  �   �:  O   �;     "<     *<  h   @<     �<      �<  V   �<  (   0=  %   Y=     =  y   �=  >   >  <   L>  l   �>  n   �>  b   e?  Y   �?  3   "@  g   V@  �   �@     ]A  8  cA     �B     �B  /   �B  W   �B  (   GC  !   pC     �C     �C     �C     �C  �   �C  C   �D  X   �D  Y   .E  �   �E  L   F  "   fF     �F     �F  =   �F  (   �F     G     +G     EG  :   aG  Y   �G      �G  S   H     kH     |H  ,   �H  )  �H  c   �I  4   SJ  B   �J  $   �J  2   �J     #K     CK  h   ZK  T   �K  [   L  �   tL  W  M  �   kN  B    O     cO     {O  =   �O  =   �O  L   P  A   _P  4   �P  8   �P  >   Q  )   NQ  B   xQ  .   �Q  A   �Q  �   ,R  l   �R  K   3S  :   S  @   �S  M   �S  F   IT  Y   �T  �   �T  V   mU  J   �U  �   V  �   �V    UW  �   ]X  -   LY  �   zY  ?   9Z  Q   yZ  >   �Z  	   
[     [  (   )[  F   R[  O   �[  ;   �[  J   %\  .   p\  �   �\  ^   "]  o   �]  a   �]     S^     p^         A   d              a   L   �      �   p   �      m   H   @   F   g   h   .   M       j   �   N   R   K   #      W   9   1      
   "   �   �              U   Q   '   O   T          �          �   ^          +   5   %   8               !      w       -       c   ;   >   =       l   �   u   |   x      7   e              P   �   I   n   J   k           )   \           q   6   �   i   �   C                         {      t   	   ]          B   b           G   <   Z           �   3   �              }   �   4   /       Y   z   v                 &   *         o   �   $          [   D                  X   :   ?   s           f   E      _   0   `   y          (                 �   �           S   ~   r   V           �              2   ,   �           A new option allows to replace the host domain used by Omeka as internal SP server with the host name used in public. A new option allows to set groups for new users (module Group). A new option allows to set the page to redirect after login. A path is set for the certificate, but it does not contain a directory "certs" with files "sp.crt" and "sp.key". Active services Add an idp Allows to get a more precise role than the default "researcher" or "guest". List of IdP and Omeka roles separated by "=". For security, admin roles are disabled: update the user manually once created. An error occurred during creation of the x509 certificate: {msg} An issue occurred during decryption with SP private key. It may not the good one. Append idp links to login view Attachment (download in browser) Attributes map between IdP and Omeka Automatic Automatic (set the url and the id and data will be automatically filled, checked and updated) Automatic registering is disabled. Automatic, except entity id (fix possible issue with reverse proxies) Basic (xml metadata without prefixes) Buttons Create an x509 certificate for the SP (require the three previous fields be empty) Create your password via your identity provider. Data to store in the certificate to create (optional) Default Groups given to newly created users using the Group Module Default redirect page after login Default role for new users when not configured in idp Direct login Federation For Shibboleth, it may be "https://idp.example.org/idp/shibboleth". For security, the default role cannot be an admin one. The default role was set to {role}. Full url set in attribute `Location` of xml element `<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`, for example "https://idp.example.org/idp/profile/SAML2/Redirect/SLO". Full url set in attribute `Location` of xml element `<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`, for example "https://idp.example.org/idp/profile/SAML2/Redirect/SSO". Full url set in attribute `entityID` of xml element `<md:EntityDescriptor>`, for example "https://idp.example.org". For some IdP, the scheme must not be set, so try "idp.example.org" too. Furthermore, IdP keys still need to be mapped, at least for name. Groups IdP Entity Id IdP metadata url (allow to get and update settings automatically) IdP name Identity providers (IdP) If not set, it will be fetched from the IdP url, if available. Include default login link Inline (display in browser) Input element It is now possible to config and update IdPs automatically with IdP metadata url. It is now possible to create the x509 certificate of the SP. It is now possible to define a default role. It is now possible to define a federation of idps like Renater instead of individual idps. It is now possible to define a specific entity id (default is the url of the site). It is now possible to force login via SSO, so to disallow local login. It is now possible to manage IdPs with a urn as entity id. It is now possible to manage multiple IdPs. It is now possible to map IdP and Omeka roles and settings. It is now possible to set an IdP manually. Warning: the certificate of IdP set manually will not be updated automatically. Links List of IdP and Omeka keys separated by "=". IdP keys can be canonical or friendly ones. Managed Omeka keys are "email", "name" and "role". Other options, like "locale", "userprofile_param", are stored in user settings. Log in (SSO) Log out (SLS) Login with your identity provider Manual (not recommended, because most certificates have a limited lifetime) Metadata content disposition Metadata content type Metadata mode Move this idp down Move this idp up No IdP with this name. No email provided or mapped. Available canonical attributes for this IdP: {keys}. Available friendly attributes for this IdP: {keys_2}. No email provided to log in or register. No issue found on IdP public certificate of "{idp}". No issue found on SP public certificate and private key. No name provided or mapped. Available canonical attributes for this IdP: {keys}. Available friendly attributes for this IdP: {keys_2}. Path for SP certificates (outside of webserver or protected) Public X.509 certificate of the IdP Register (JIT) Remove this idp Replace host name when SP is behind a proxy Roles map between IdP and Omeka SP name id format SP private key (x509) SP public certificate (x509) SSO service has an error in configuration: {exception} SSO service is not available. Ask admin to config it. SSO service is unavailable. SSO service is unavailable. Ask admin to config it. Select  Select a federation… Select name id format if needed Set "home" for home page (admin or public), "site" for the current site home, "top" for main public page, "me" for guest account, or any path starting with "/", including "/" itself for main home page. Set a specific service provider entity id (default is the uri of the current host) Single logout service failed: {errors} Single logout service failed: {errors}. {error_last} Single sign-on failed: {errors} Single sign-on failed: {errors}. {error_last} Single sign-on is disabled. Single sign-on login links Some IdP don’t manage xml prefixes in metadata, so they may be removed. Some IdP require metadata to be downloadable, not inline. Some IdP require response header content type to be simple xml. Some idp require certificates. If needed and if not set via a path, paste public certificate here. Take care to renew them when needed. Some idp require certificates. If needed and not set in next fields, set the path to it. It should contains a directory "certs/" with at least "sp.crt" and "sp.key". It must be protected, for example with a .htaccess. Take care to renew them when needed. Some idp require certificates. If needed and not set via a path, paste private key here. Take care to renew them when needed. Static user settings for new users Successfully logged in. Successfully logged out. The IdP "{idp}" has no available metadata. The IdP "{idp}" has no valid xml metadata. The IdP #{index} has no url and no id and is not valid. The IdP public certificate of "{idp}" is not valid. The IdP url "{url}" is not valid. The IdP url {url} does not return any metadata. The IdP url {url} does not return valid xml metadata. The SP private key is not valid. The SP private key is set, but not the public certificate. The SP public certificate is not valid. The SP public certificate is set, but not the private key. The certicate cannot be created when fields "certificate path", "x509 certificate", or "x509 private key" are filled. The certificate is generated for a century with the default data of the server or the data below. The federated IdP #{index} has no id and is not valid. The federation url "{url}" is not a valid url. The federation url {url} does not return any metadata. The federation url {url} does not return valid xml metadata. The idp "{idp}" seems to be invalid and has no id. The idp "{idp}" was manually filled and is not checked neither updated. The list of idps can be displayed on any page via the theme block and helper or via module Guest. The local federation file "{file}" does not exist or is not readable. The module %1$s should be upgraded to version %2$s or later. The optional data keys are: countryName, stateOrProvinceName, localityName, organizationName, organizationalUnitName, commonName, and emailAddress. The setting "template" was moved to the new block layout settings available since Omeka S v4.1. You may check pages for styles: {json} The settings "heading" was removed from block Sso login links. New blocks "Heading" or "Html" were prepended to all blocks that had a filled heading. You may check pages for styles: {json} The template files for the block Sso login links should be moved from "view/common/block-layout" to "view/common/block-template" in your themes. You may check your themes for pages: {json} The x509 certificate was created successfully. This option allows to replace the host domain used by Omeka as internal SP server with the host name used in public. The protocol (http or https) should be included. Unable to decrypt message with SP private key. Unable to encrypt message with IdP public certificate of "{idp}". Unable to encrypt message with SP public certificate. Undefined Update mode Update user name Update your password via your identity provider. Url of the IdP single log out (SLO) service endpoint Url of the IdP single sign-on (SSO) service endpoint Urls for SSO and SLS should be provided if enabled. User "{email}" is inactive. Value to set in xml element `<md:NameIDFormat>`. Let empty to use the default value (unspecified). Warning: some IdPs hide the name, so you may fill it yourself. When the metadata url of an IdP is set, its form will be automatically filled and updated each day. You cannot set a path to the certificate and provide them in fields at the same time. application/samlmetadata+xml application/xml Project-Id-Version: 
Report-Msgid-Bugs-To: 
PO-Revision-Date: 
Last-Translator: Daniel Berthereau <Daniel.fr@Berthereau.net>
Language-Team: 
Language: fr
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Generator: Poedit 3.2.2
 Une nouvelle option permet de remplacer le domaine hôte utilisé par Omeka en tant que serveur SP interne par le nom d’hôte utilisé en public. Une nouvelle option permet de définir les groupes pour les nouveaux utilisateurs (module Groupe). Une nouvelle option permet de définir la page de redirection après connexion. Un chemin est défini pour le certificat, mais il ne contient pas le dossier « certs » avec les fichiers « sp.crt » et « sp.key ». Services actifs Ajouter un idp Permet d’obtenir un rôle plus précis que le rôle par défaut « chercheur » ou « invité ». Liste des rôles IdP et Omeka séparés par « = ». Pour des raisons de sécurité, les rôles d'administrateur sont désactivés : mettez l'utilisateur à jour manuellement une fois qu'il a été créé. Une erreur est survenue lors de la création du certificat x509 : {msg} Un problème s’est produit lors du décryptage avec la clé privée SP. Il se peut qu’elle ne soit pas la bonne. Ajouter les liens IdP à la vue de connexion Pièce jointe (télécharger dans le navigateur) Alignement des valeurs entre l’IdP et Omeka Automatique Automatique (définir l’url et l’identifiant et les données seront automatiquement remplis, vérifiés et mis à jour) L’inscription automatique est désactivée. Automatique, sauf l’identifiant de l’entité (résolution d’un éventuel problème avec les proxys inversés) Basique (métadonnées xml sans préfixes) Boutons Créer un certificat x509 pour le SP (si les trois champs précédents sont vides) Créez votre mot de passe via votre fournisseur d’identité. Valeurs à enregistrer dans le certificat à créer (facultatif) Groupes par défaut définis pour les nouveaux utilisateurs (module Groupe) Page de redirection par défaut après connexion Rôle par défaut pour les nouveaux utilisateurs s’il n’est pas configuré par l’idp Connexion directe Fédération Pour Shibboleth, cela peut être « https://idp.example.org/idp/shibboleth ». Par sécurité, le rôle par défaut ne peut pas être un rôle administrateur. Le rôle par défaut a été mis à {role}. URL complète définie dans l’attribut `Location` de l’élément xml `<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`, par exemple « https://idp.example.org/idp/profile/SAML2/Redirect/SLO ». URL complète définie dans l'attribut `Location` de l'élément xml `<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect">`, par exemple « https://idp.example.org/idp/profile/SAML2/Redirect/SSO ». URL complète définie dans l’attribut `entityID` de l'élément xml `<md:EntityDescriptor>`, par exemple « https://idp.example.org ». Pour certains IdP, le schéma ne doit pas être défini, essayez donc aussi « idp.example.org ». En outre, les clés IdP doivent toujours être alignées, au moins pour le nom. Groupes Id de l’entité IdP Url des métadonnées de l’IdP (permet d'obtenir et de mettre à jour les paramètres automatiquement) Nom de l’IdP Fournisseurs d’identité (IdP) Si elle n’est pas définie, elle sera extraite de l’url de l’IdP, si disponible. Inclure le lien de connexion par défaut Inline (affichage dans le navigateur) Élément de saisie Il est désormais possible de configurer et de mettre à jour automatiquement les IdP avec l’url des métadonnées IdP. Il est désormais possible de créer le certificat x509 du SP. Il est désormais possible de définir un rôle par défaut. Il est désormais possible de définir une fédération d’idps comme Renater au lieu d’idps individuels. Il est désormais possible de définir une id d’entité. L’id d’entité par défaut est l’url du site. Il est maintenant possible de forcer la connexion via SSO, afin d’interdire la connexion locale. Il est désormais possible de gérer des IdPs qui utilisent une URN comme id d’entité. Il est désormais possible de gérer plusieurs IdP. Il est désormais possible de faire correspondre les rôles et les paramètres de l’IdP et d’Omeka. Il est désormais possible de définir un IdP manuellement. Attention : le certificat de l’IdP défini manuellement ne sera pas mis à jour automatiquement. Liens Liste des clés IdP et Omeka séparées par des « = ». Les clés IdP peuvent être canoniques ou simplifiées. Les clés Omeka gérées sont « email », « name » et « role ». Les autres options, comme « locale », « userprofile_param », sont stockées dans les paramètres de l'utilisateur. Connexion (SSO) Déconnexion (SLS) Se connecter avec son fournisseur d’identité Manuel (non recommandé, car la plupart des certificats ont une durée de vie limitée) Disposition du contenu des métadonnées Type de contenu des métadonnées Mode des métadonnées Déplacer cet idp vers le bas Déplacer cet idp vers le haut Aucun IdP avec ce nom. Pas d’email fourni ou aligné. Attributs canoniques disponibles pour cet IdP : {keys}. Attributs simplifiés disponibles pour cet IdP : {keys_2}. Aucun courriel n’est fourni pour se connecter ou s’enregistrer. Aucun problème n’a été détecté sur le certificat public de l’IdP « {idp} ». Aucun problème n’a été constaté pour le certificat public et la clé privée du SP. Pas de nom fourni ou aligné. Attributs canoniques disponibles pour cet IdP : {keys}. Attributs simplifiés disponibles pour cet IdP : {keys_2}. Chemin d’accès aux certificats SP (en dehors du serveur web ou protégé) Certificat public X.509 de l’IdP Enregistrement (JIT) Supprimer cet idp Remplacer le nom d’hôte quand le SP est derrière un proxy Alignement entre les rôles IdP et Omeka Format du nom du SP Clé privée du SP (x509) Certificat public SP (x509) Le service SSO a une erreur de configuration : {exception} Le service SSO n’est pas disponible. Demander à votre administrateur de le configurer. Le service SSO est indisponible. Le service SSO est indisponible. Demander à votre administrateur de le configurer. Menu déroulant  Choisir une fédération… Choisir le format de l’id du nom si besoin Indiquer « home » pour la page d’accueil (admin ou public), « site » pour l’accueil du site actuel, « top » pour l’accueil du site principal, « me » pour le compte utilisateur, ou tout chemin commençant par « / », y compris « / » pour la page d’accueil principale. Définir un id d’entité spécifique pour le fournisseur de services (uri du serveur par défaut) Le service SLO de déconnexion a échoué : {errors} Le service SLO de déconnexion a échoué : {errors}. {error_last} Le service SSO a échoué : {errors} Le service SSO a échoué : {errors}. {error_last} Le service SSO est désactivé. Liens de connexion SSO Certains IdP ne gèrent pas les préfixes xml dans les métadonnées, ils peuvent donc être supprimés. Certains IdP exigent que les métadonnées soient téléchargeables et non en ligne. Certains IdP exigent que le type de contenu de l’en-tête de réponse soit un simple xml. Certains IDP nécessitent des certificats. Si besoin et non défini via un fichier, collez le certificat public ici. Veillez à les renouveler si nécessaire. Certains IDP nécessitent des certificats. Si besoin et non défini dans les champs suivants, le chemin d’accès peut être indiqué ici. Il doit contenir un répertoire « certs/ » avec au moins « sp.crt » « sp.key ». Il doit être protégé, par exemple avec un .htaccess. Veillez à les renouveler lorsque cela est nécessaire. Certains IDP nécessitent des certificats. Si besoin et non définie via un fichier, vous pouvez coller la clé privée ici. Veillez à les renouveler lorsque cela est nécessaire. Paramètres d'utilisateur statiques pour les nouveaux utilisateurs Connecté avec succès. Déconnecté avec succès. L’IdP « {idp} » n’a pas de métadonnées disponibles. L’IdP « {idp} » n’a pas de métadonnées xml valides. L’IdP #{index} n’a pas d’url ni d’identifiant et n’est pas valide. Le certificat public de l’IdP « {idp} » n’est pas valide. L’url de l’IdP « {url} » n’est pas valide. L’url de l’IdP {url} ne renvoie aucune métadonnée. L’url IdP {url} ne renvoie pas de métadonnées xml valides. La clé privée du SP n’est pas valide. La clé privée du SP est définie, mais pas le certificat public. Le certificat public du SP n’est pas valide. Le certificat public du SP est défini, mais pas la clé privée. Le certificat ne peut pas être créé quand les champs « chemin du certificat », « certificat x509 » ou « clé privée x509 » sont définis. Le certificat est créé pour un siècle avec les données par défaut du serveur ou les valeurs ci-dessous. L’IdP fédéré #{index} n’a pas d’identifiant et n’est pas valide. L’url de la fédération « {url} » n'est pas valide. L’url de la fédération {url} ne renvoie aucune métadonnée. L’url de la fédération {url} ne renvoie pas de métadonnées xml valides. L’IdP « {idp} » n’a pas d’identifiant et n’est pas valide. L’IdP « {idp} » a été rempli manuellement et n’est ni vérifié ni mis à jour. La liste des idps peut être affichée sur n’importe quelle page via le bloc de thème et du view helper ou via le module Guest. Le fichier local pour la fédération {file} n’existe pas ou n’est pas accessible. Le module %1$s doit être mis à niveau à la version %2$s ou supérieure. Les clés de données possibles sont : countryName, stateOrProvinceName, localityName, organizationName, organizationalUnitName, commonName et emailAddress. Le paramètre « template » a été déplacé dans les nouveaux paramètres de bloc depuis Omeka S v4.1. Vous pouvez vérifier les pages pour les styles : {json} Le paramètre « heading » (titre) a été supprimé des blocs de liens de connexion Sso. De nouveaux blocs « Titre » ou « Html » ont été ajoutés à tous les blocs qui avaient un titre rempli. Vous pouvez vérifier les pages pour les styles : {json} Les fichiers de modèle pour les liens de connexion du bloc Sso doivent être déplacés de « view/common/block-layout » à « view/common/block-template » dans vos thèmes. Vous pouvez vérifier vos thèmes pour les pages : {json} The certificat x509 was created correctement. Cette option permet de remplacer le domaine hôte utilisé par Omeka en tant que serveur SP interne par le nom d’hôte utilisé en public. Le protocole (http ou https) doit être indiqué. Impossible de décrypter le message avec la clé privée du SP. Impossible de chiffrer le message avec le certificat public IdP de « {idp} ». Impossible de crypter le message avec le certificat public SP. Indéfini Mode de mise à jour Mettre à jour le nom de l’utilisateur Mettez à jour votre mot de passe via votre fournisseur d’identité. Url du point d’extrémité du service de déconnexion unique (SLO) de l’IdP Url du service d’authentification unique (SSO) de l’IdP Les urls pour SSO et SLS doivent être fournies si le service est activé. L’utilisateur « {email} » est inactif. Valeur à définir dans l’élément xml `<md:NameIDFormat>`. Laisser vide pour utiliser la valeur par défaut (non-spécifiée). Attention : certains IdPs cachent le nom et vous devez donc le remplir vous-même dans ce cas. Quand l’url des métadonnées de l’IdP est mise, le formulaire est automatiquement mis à jour chaque jour. Vous ne pouvez pas indiquer le chemin du certificat et le fournir dans les champs en même temps. application/samlmetadata+xml application/xml 