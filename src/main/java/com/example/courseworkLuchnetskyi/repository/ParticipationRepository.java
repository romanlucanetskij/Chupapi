package com.example.courseworkLuchnetskyi.repository;

import com.example.courseworkLuchnetskyi.model.Participation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ParticipationRepository extends JpaRepository<Participation, Long> {
    List<Participation> findByTournamentId(Long tournamentId);
    List<Participation> findByTeamId(Long teamId);
}
