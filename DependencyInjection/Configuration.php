<?php

namespace Stg\Bundle\CasBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    const CAS_VERSION_3_0 = '3.0';
    const CAS_VERSION_2_0 = '2.0';
    const CAS_VERSION_1_0 = '1.0';

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('cas');
        $rootNode = $treeBuilder->getRootNode();
        $rootNode
            ->children()
                ->scalarNode('hostname')
                    ->defaultValue('https://dsso.santafe.gob.ar/')
                    ->example('example.org')
                    ->info('Enter the hostname of the CAS server.')
                ->end()
                ->integerNode('port')
                    ->defaultValue(443)
                    ->example('443')
                    ->info('Server cas port')
                ->end()
                ->scalarNode('url')
                    ->defaultValue('/service-auth')
                    ->example('/service-auth')
                    ->info('REQUEST_PATH of the CAS server.')
                ->end()
                ->scalarNode('service_base_url')
                    ->defaultValue('http://localhost:80')
                    ->example('http://localhost:80')
                    ->info('Url del servicio que utiliza cas')
                ->end()
                ->booleanNode('debug')
                    ->defaultValue(false)
                    ->example('true')
                    ->info('If true log in file.')
                ->end()
                ->enumNode('version')
                    ->values([
                        self::CAS_VERSION_3_0,
                        self::CAS_VERSION_2_0,
                        self::CAS_VERSION_1_0,
                    ])
                    ->defaultValue(self::CAS_VERSION_3_0)
                    ->example('3.0')
                    ->info('Version of the CAS Server.')
                ->end()
                ->scalarNode('user')
                    ->defaultValue('cuil')
                    ->example('cuil')
                    ->info('Atributo utilizado como identificador')
                ->end()
                ->scalarNode('logout_redirect')
                    ->defaultValue('')
                    ->example('home')
                    ->info('Url after logout successfull')
                ->end()
                ->scalarNode('login_failure')
                    ->defaultValue('')
                    ->example('failure_path')
                    ->info('Url when login failure')
                ->end()
                ->arrayNode('firewalls_on')
                    ->prototype('scalar')
                        ->defaultValue([])
                        ->example("['rc_stg_1','rc_stg_2']")
                        ->info('Aca va la lista de firewalls donde escucha para hacer logout')
                    ->end()
                ->end()

            ->end();

        return $treeBuilder;
    }
}
