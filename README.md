
# Library

Implementation of JWT using https://github.com/web-token libraries

# Usage

This project has a structure based on DDD and hexagonal architecture.

If your application has a dependency injection system you can use the interface ```Abuenosvinos\Domain\Adapter\Jwt\JwtAdapter``` (Port) and populate the implementation with the classes in ```Abuenosvinos\Infrasctructure\Jwt``` (Adapter).

If not, you can see how to use it in the ```Abuenosvinos\Tests\Shared\Infrastructure\Jwt\JwtTest``` class.

# Test

docker run --rm -v $(pwd):/app php:8.1 /app/vendor/bin/phpunit /app/tests
