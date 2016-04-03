<?php

namespace Seat\Addon\Auth;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider as LaravelServiceProvider;

class ServiceProvider extends LaravelServiceProvider {

	/**
	 * Bootstrap the application services.
	 *
	 * @param \Illuminate\Routing\Router $router
	 */
	public function boot(Router $router) {
		if (!$this->app->routesAreCached()) { include __DIR__ . '/Http/routes.php'; }

		$this->publishes([
			__DIR__ . '/../config/' => config_path(),
		]);

		$this->mergeConfigFrom(__DIR__ . '/../config/addon.auth.php', 'addon.auth');
	}

	/**
	 * Register the application services.
	 *
	 * @return void
	 */
	public function register() {
		//
	}

}
