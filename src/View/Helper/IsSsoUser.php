<?php declare(strict_types=1);

namespace SingleSignOn\View\Helper;

use Laminas\View\Helper\AbstractHelper;
use Omeka\Entity\User;
use SingleSignOn\Mvc\Controller\Plugin\IsSsoUser as IsSsoUserPlugin;

class IsSsoUser extends AbstractHelper
{
    /**
     * @var \SingleSignOn\Mvc\Controller\Plugin\IsSsoUser
     */
    protected $isSsoUserPlugin;

    public function __construct(IsSsoUserPlugin $isSsoUser)
    {
        $this->isSsoUserPlugin = $isSsoUser;
    }

    /**
     * Check if a user is authenticated via module Single Sign-On.
     */
    public function __invoke(?User $user): bool
    {
        return $this->isSsoUserPlugin->__invoke($user);
    }
}
