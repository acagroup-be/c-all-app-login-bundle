<?php

declare(strict_types=1);

namespace vBridgeCloud\CallLoginBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('call_login');

        $treeBuilder->getRootNode()
            ->children()
                ->scalarNode('public_url')
                    ->info('The public URL the login app is available through')
                    ->isRequired()
                ->end()
                ->scalarNode('internal_url')
                    ->info('Internal URL for the login app (server-to-server calls)')
                    ->isRequired()
                ->end()
                ->scalarNode('client_id')->isRequired()->end()
                ->scalarNode('client_secret')->isRequired()->end()
                ->scalarNode('public_key')
                    ->info('RSA public key of the login app used to verify id_tokens: PEM contents, a file path or a file:// URI')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('login_redirect_path')->defaultValue('home')->end()
                ->scalarNode('oauth_redirect_path')->defaultValue('call_login_authorize')->end()
            ->end();

        return $treeBuilder;
    }
}
