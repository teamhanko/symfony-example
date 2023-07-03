<?php

declare(strict_types=1);

namespace App\Twig;

use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class HankoExtension extends AbstractExtension
{
    private string $hankoApiUrl;

    public function __construct(string $hankoApiUrl)
    {
        $this->hankoApiUrl = $hankoApiUrl;
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('hanko_api_url', [$this, 'getHankoApiUrl']),
        ];
    }

    public function getHankoApiUrl(): string
    {
        return $this->hankoApiUrl;
    }
}
