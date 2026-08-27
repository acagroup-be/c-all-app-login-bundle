<?php

declare(strict_types=1);

namespace vBridgeCloud\CallLoginBundle;

use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use vBridgeCloud\CallLoginBundle\DependencyInjection\CallLoginExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

final class CallLoginBundle extends Bundle
{
    public function getContainerExtension(): ExtensionInterface
    {
        return new CallLoginExtension();
    }
}
