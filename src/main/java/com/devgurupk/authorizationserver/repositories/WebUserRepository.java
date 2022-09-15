package com.devgurupk.authorizationserver.repositories;



import com.devgurupk.authorizationserver.domain.WebUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.Optional;


public interface WebUserRepository extends JpaRepository<WebUser, Long>, JpaSpecificationExecutor<WebUser>
{
    Optional<WebUser> findByEmailIgnoreCaseAndStatus(String userName, Integer status);

    Optional<WebUser> findByWebIdAndActiveAndStatus(Long webId, boolean active, Integer status);

    int countByEmailIgnoreCaseAndStatus(String userName, Integer status);
}
