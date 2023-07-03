<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use App\Repository\UserRepository;
use App\Security\HankoUser;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * Controller used to manage the application security.
 * See https://symfony.com/doc/current/security/form_login_setup.html.
 *
 * @author Ryan Weaver <weaverryan@gmail.com>
 * @author Javier Eguiluz <javier.eguiluz@gmail.com>
 */
class SecurityController extends AbstractController
{
    use TargetPathTrait;

    /*
     * The $user argument type (?User) must be nullable because the login page
     * must be accessible to anonymous visitors too.
     */
    #[Route('/login', name: 'security_login')]
    public function login(
        #[CurrentUser] ?User $user,
        Request $request,
        AuthenticationUtils $helper,
    ): Response {
        // if user is already logged in, don't display the login page again
        if ($user) {
            return $this->redirectToRoute('blog_index');
        }

        // this statement solves an edge-case: if you change the locale in the login
        // page, after a successful login you are redirected to a page in the previous
        // locale. This code regenerates the referrer URL whenever the login page is
        // browsed, to ensure that its locale is always the current one.
        $this->saveTargetPath($request->getSession(), 'main', $this->generateUrl('admin_index'));

        return $this->render('security/login.html.twig', [
            // last username entered by the user (if any)
            'last_username' => $helper->getLastUsername(),
        ]);
    }

    /*
     * The $user argument type (?User) must be nullable because the login page
     * must be accessible to anonymous visitors too.
     */
    #[Route('/register', name: 'security_register', methods: ['GET', 'POST'])]
    public function register(
        #[CurrentUser] ?UserInterface $user,
        Request $request,
        EntityManagerInterface $entityManager,
        UserRepository $userRepository
    ): Response {
        // if user is not a HankoUser or does not exist, don't display the register page
        // as only HankoUsers can be registered
        if (!$user instanceof HankoUser) {
            return $this->redirectToRoute('blog_index');
        }

        // this statement solves an edge-case: if you change the locale in the login
        // page, after a successful login you are redirected to a page in the previous
        // locale. This code regenerates the referrer URL whenever the login page is
        // browsed, to ensure that its locale is always the current one.
        $this->saveTargetPath($request->getSession(), 'main', $this->generateUrl('admin_index'));

        $requestData = $request->request->all();
        if (isset($requestData['user']['email'])) {
            $databaseUser = $userRepository->findOneByEmail($requestData['user']['email']);
        }

        if (!isset($databaseUser)) {
            $databaseUser = new User();
        }

        $databaseUser->setHankoSubjectId($user->getUserIdentifier());
        $userForm = $this->createForm(UserType::class, $databaseUser);

        $userForm->handleRequest($request);

        if ($userForm->isSubmitted() && $userForm->isValid()) {
            $userEmail = $databaseUser->getEmail();
            \assert(!empty($userEmail), 'User email should not be empty');
            $databaseUser->setUsername($userEmail);

            $entityManager->persist($databaseUser);
            $entityManager->flush();

            return $this->redirectToRoute('blog_index');
        }

        return $this->render('security/register.html.twig', [
            'userForm' => $userForm,
        ]);
    }

    /**
     * This is the route the user can use to logout.
     *
     * But, this will never be executed. Symfony will intercept this first
     * and handle the logout automatically. See logout in config/packages/security.yaml
     */
    #[Route('/logout', name: 'security_logout')]
    public function logout(): void
    {
        throw new \RuntimeException('This should never be reached!');
    }
}
