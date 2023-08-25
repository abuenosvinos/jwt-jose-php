
# Library

Implementation of JWT using https://github.com/web-token libraries

# Usage

This project has a structure based on DDD and hexagonal architecture.

If your application has a dependency injection system you can use the interface ```Abuenosvinos\Domain\Adapter\Jwt\JwtAdapter``` (Port) and populate the implementation with the classes in ```Abuenosvinos\Infrastructure\Jwt``` (Adapter).

If not, you can see how to use it in the ```Abuenosvinos\Tests\Infrastructure\Jwt\JwtTest``` class.

# Preparation

```
docker run --rm -t -u $(id -u ${USER}):$(id -g ${USER}) -v $(pwd):/app composer:2 install
```

# Test

```
docker run --rm -t -u $(id -u ${USER}):$(id -g ${USER}) -v $(pwd):/app -w /app php:8.1 /app/vendor/bin/phpunit
```
