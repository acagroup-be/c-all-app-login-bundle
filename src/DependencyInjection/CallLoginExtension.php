<?php

declare(strict_types=1);

namespace vBridgeCloud\CallLoginBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

final class CallLoginExtension extends Extension
{
    /**
     * @param array<mixed> $configs
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');

        $config = $this->processConfiguration(new Configuration(), $configs);

        $container->getDefinition('call_login.id_token_verifier')
            ->setArgument('$publicKey', $config['public_key'])
            ->setArgument('$clientId', $config['client_id']);

        $container->getDefinition('call_login.entrypoint')
            ->setArgument('$publicLoginUrl', $config['public_url'])
            ->setArgument('$clientId', $config['client_id'])
            ->setArgument('$oauthRedirectPath', $config['oauth_redirect_path']);

        $container->getDefinition('call_login.authenticator')
            ->setArgument('$publicLoginUrl', $config['public_url'])
            ->setArgument('$internalLoginUrl', $config['internal_url'])
            ->setArgument('$clientId', $config['client_id'])
            ->setArgument('$clientSecret', $config['client_secret'])
            ->setArgument('$oauthRedirectPath', $config['oauth_redirect_path'])
            ->setArgument('$loginRedirectPath', $config['login_redirect_path']);

        $container->getDefinition('call_login.user_provider')
            ->setArgument('$internalLoginUrl', $config['internal_url']);
    }
}
